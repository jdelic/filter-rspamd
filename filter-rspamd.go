//
// Copyright (c) 2019 Gilles Chehade <gilles@poolp.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

package main

import (
	"flag"
	"fmt"
	"github.com/jdelic/opensmtpd-filters-go"
	"strings"

	"encoding/json"
	"net/http"
)

var rspamdURL *string

type rspamd struct {
	Score         float32
	RequiredScore float32 `json:"required_score"`
	Subject       string
	Action        string
	Messages      struct {
		SMTP string `json:"smtp_message"`
	} `json:"messages"`
	DKIMSig string `json:"dkim-signature"`
	Headers struct {
		Remove map[string]int8        `json:"remove_headers"`
		Add    map[string]interface{} `json:"add_headers"`
	} `json:"milter"`
	Symbols map[string]interface{} `json:"symbols"`
}

type filterRspamd struct {
	opensmtpd.SessionTrackingMixin
}

func (f *filterRspamd) GetName() string {
	return "filter-rspamd"
}

type rspamdAction struct {
	action string
	response string
}


func (f *filterRspamd) MessageComplete(token string, session *opensmtpd.SMTPSession) {
	replies := make(chan rspamdAction)
	go rspamdQuery(replies, token, session)
	action := <- replies

	switch action.action {
	case "flush":
		opensmtpd.FlushMessage(token, session)
		opensmtpd.Proceed(token, session.Id)
	case "reject":
		if action.response == "" {
			action.response = "message rejected"
		}
		opensmtpd.HardReject(token, session.Id, action.response)
	case "greylist":
		if action.response == "" {
			action.response = "try again later"
		}
		opensmtpd.Greylist(token, session.Id, action.response)
	case "soft reject":
		if action.response == "" {
			action.response = "try again later"
		}
		opensmtpd.SoftReject(token, session.Id, action.response)
	default:
		opensmtpd.Proceed(token, session.Id)
	}
}

func rspamdQuery(replyChan chan<- rspamdAction, token string, session *opensmtpd.SMTPSession) {
	r := strings.NewReader(strings.Join(session.Message, "\n"))
	client := &http.Client{}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/checkv2", *rspamdURL), r)
	if err != nil {
		opensmtpd.FlushMessage(token, session)
		return
	}

	req.Header.Add("Pass", "All")
	if !strings.HasPrefix(session.Src, "unix:") {
		if session.Src[0] == '[' {
			ip := strings.Split(strings.Split(session.Src, "]")[0], "[")[1]
			req.Header.Add("Ip", ip)
		} else {
			ip := strings.Split(session.Src, ":")[0]
			req.Header.Add("Ip", ip)
		}
	} else {
		req.Header.Add("Ip", "127.0.0.1")
	}

	req.Header.Add("Hostname", session.Rdns)
	req.Header.Add("Helo", session.HeloName)
	req.Header.Add("MTA-Name", session.MtaName)
	req.Header.Add("Queue-Id", session.Msgid)
	req.Header.Add("From", session.MailFrom)

	if session.UserName != "" {
		req.Header.Add("User", session.UserName)
	}

	for _, rcptTo := range session.RcptTo {
		req.Header.Add("Rcpt", rcptTo)
	}

	resp, err := client.Do(req)
	if err != nil {
		replyChan <- rspamdAction{
			action:   "flush",
			response: "",
		}
		return
	}

	defer resp.Body.Close()

	rr := &rspamd{}
	if err := json.NewDecoder(resp.Body).Decode(rr); err != nil {
		replyChan <- rspamdAction{
			action:   "flush",
			response: "",
		}
		return
	}

	switch rr.Action {
	case "reject":
		fallthrough
	case "greylist":
		fallthrough
	case "soft reject":
		replyChan <- rspamdAction{
			action:   rr.Action,
			response: rr.Messages.SMTP,
		}
		return
	}

	if rr.DKIMSig != "" {
		opensmtpd.WriteMultilineHeader(token, session.Id, "DKIM-Signature", rr.DKIMSig)
	}

	if rr.Action == "add header" {
		opensmtpd.DatalineReply(token, session.Id, fmt.Sprintf("%s: %s\n", "X-Spam", "yes"))
		opensmtpd.DatalineReply(token, session.Id, fmt.Sprintf("%s: %s\n", "X-Spam-Score",
			fmt.Sprintf("%v / %v", rr.Score, rr.RequiredScore)))

		if len(rr.Symbols) != 0 {
			buf := ""
			for k, _ := range rr.Symbols {
				if buf == "" {
					buf = fmt.Sprintf("%s%s", buf, k)
				} else {
					buf = fmt.Sprintf("%s,\n\t%s", buf, k)
				}
			}
			opensmtpd.WriteMultilineHeader(token, session.Id, "X-Spam-Symbols", buf)
		}
	}

	if len(rr.Headers.Add) > 0 {
		authHeaders := map[string]string{}

		for h, t := range rr.Headers.Add {
			switch v := t.(type) {
			/**
			 * Authentication headers from Rspamd are in the form of:
			 * ARC-Seal : { order : 1, value : text }
			 * ARC-Message-Signature : { order : 1, value : text }
			 * Unfortunately they all have an order of 1, so we
			 * make a map of them and print them in proper order.
			 */
			case map[string]interface{}:
				if h != "" {
					v, ok := v["value"].(string)
					if ok {
						authHeaders[h] = v
					}
				}
			/**
			 * Regular X-Spam headers from Rspamd are plain strings.
			 * Insert these at the top.
			 */
			case string:
				opensmtpd.WriteMultilineHeader(token, session.Id, h, v)
			default:
			}
		}

		/**
		 * Prefix auth headers to incoming mail in proper order.
		 */
		if len(authHeaders) > 0 {
			hdrs := []string{
				"ARC-Seal",
				"ARC-Message-Signature",
				"ARC-Authentication-Results",
				"Authentication-Results"}

			for _, h := range hdrs {
				if authHeaders[h] != "" {
					opensmtpd.WriteMultilineHeader(token, session.Id, h, authHeaders[h])
				}
			}
		}
	}

	inhdr := true
	rmhdr := false

LOOP:

	for _, line := range session.Message {
		if line == "" {
			inhdr = false
			rmhdr = false
		}

		if inhdr && rmhdr && (strings.HasPrefix(line, "\t") ||
			strings.HasPrefix(line, " ")) {
			continue
		} else {
			rmhdr = false
		}

		if inhdr && len(rr.Headers.Remove) > 0 {
			for h := range rr.Headers.Remove {
				if strings.HasPrefix(line, fmt.Sprintf("%s:", h)) {
					rmhdr = true
					continue LOOP
				}
			}
		}
		if rr.Action == "rewrite subject" && inhdr && strings.HasPrefix(line, "Subject: ") {
			opensmtpd.DatalineReply(token, session.Id, fmt.Sprintf("Subject: %s", rr.Subject))
		} else {
			opensmtpd.DatalineReply(token, session.Id, line)
		}
	}
	opensmtpd.DatalineEnd(token, session.Id)
}

func main() {
	rspamdURL = flag.String("url", "http://localhost:11333", "rspamd base url")
	flag.Parse()

	opensmtpd.Run(opensmtpd.NewFilter(&filterRspamd{}))
}
