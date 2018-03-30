r'''
Copyright 2014 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''
from nogotofail.mitm.connection.handlers.connection import SelfSignedMITM
from nogotofail.mitm.connection.handlers.connection import handlers
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.connection.handlers import preconditions
from nogotofail.mitm import util


@handler(handlers, default=True)
@preconditions.requires_files(files=["expired-cert.pem"])
class ExpiredCertificateMITM(SelfSignedMITM):

    name = "expiredcertificate"
    description = (
        "Attempts to MiTM using an expired certificate."
        " NOTE: requires ./expired-cert.pem have an expired cert and private key")
    certificate_file = "expired-cert.pem"
    vuln = util.vuln.VULN_TLS_EXPIRED_CERTIFICATE

    @property
    def certificate(self):
        return util.extras.get_extras_path(self.certificate_file)
    def on_certificate(self, server_cert):
        return self.certificate
