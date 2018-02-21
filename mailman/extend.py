#
# Copyright (C) 2018 Andrew Ayer
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# Except as contained in this notice, the name(s) of the above copyright
# holders shall not be used in advertising or otherwise to promote the
# sale, use or other dealings in this Software without prior written
# authorization.
#

import sys
sys.path.append('/usr/lib/python2.7/dist-packages')

import dkim
import spf
import re
from types import MethodType
from Mailman.Logging.Syslog import syslog


def message_has_valid_dkim(sender, msg):
	d = dkim.DKIM(msg.as_string())
	try:
		if not d.verify():
			return False
	except dkim.DKIMException as x:
		syslog('error', 'DKIM exception when verifying bounce recipient: %s', x)
		return False
	except Exception as x:
		syslog('error', 'Exception when verifying bounce recipient: %s', x)
		return False

	dkim_identity = d.signature_fields.get(b'i')
	if dkim_identity is not None:
		return sender.lower() == dkim_identity.lower()
	else:
		dkim_domain = d.signature_fields.get(b'd')
		sender_domain = sender.split('@', 2)[1]
		return dkim_domain.lower() == sender_domain.lower()

def message_has_valid_spf(sender, msg):
	received = msg.get_all('Received', [])
	if len(received) == 0:
		return False
	pattern = re.compile('\s*from\s+[^\s]+\s+\(([^\s]+\s+)?\[([^]]+)\]\)', re.IGNORECASE)
	match = pattern.search(received[0])
	if match is None:
		return False
	sender_ipaddr = match.group(2)
	q = spf.query(sender_ipaddr, sender, None)
	res, code, txt = q.check()
	return res == 'pass'

def sender_is_authentic(sender, msg):
	return message_has_valid_dkim(sender, msg) or message_has_valid_spf(sender, msg)

def safe_bounce_message(self, msg, msgdata, e=None):
	sender = msg.get_sender()
	if sender_is_authentic(sender, msg):
		self._original_bounce_message(msg, msgdata, e)
	else:
		syslog('vette', 'Suppressing bounce to unauthenticated sender, msgid: %s, sender: %s', msg.get('message-id', 'n/a'), sender)

def extend(mlist):
	mlist._original_bounce_message = mlist.BounceMessage
	mlist.BounceMessage = MethodType(safe_bounce_message, mlist)
