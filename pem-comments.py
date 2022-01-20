#!/usr/bin/env python3
# What I want for this tool:
# Take stdin (or a file) and comment information about pems
# optionals: color different cert/key identities
# - define what you want in the comment (subject,altNames,dates/enddate, $name)
# - color (detect pipe and disable it?)
# - noout (only comment)
# - comment prefix (default="# ")
# different types of getting info (openssl, python module)
#
# Best effort, no idea about crypto, no verification,
# only check pub to make sure certs match up
#
# example comments:
# # CN=*.example.com example.com 2022-01-11 alice1 by bob1
from typing import TextIO, List
from sys import stdin
from argparse import ArgumentParser, FileType
from textwrap import dedent, indent
from hashlib import sha256
import re
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_csr
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key)

WHITESPACE = re.compile(r"\s*")


class NotValidPEM(Exception):
    pass


class Analyser:
    pem_types = (
        {
            "start": "-----BEGIN CERTIFICATE-----",
            "end": "-----END CERTIFICATE-----",
            "type": "Certificate",
            "shell": "openssl x509 -noout -subject -ext subjectAltName \
                     -hash -issuer_hash -dates -modulus",
        },
        {
            "type": "PrivateKey",
            "start": "-----BEGIN PRIVATE KEY-----",
            "end": "-----END PRIVATE KEY-----",
            "shell": "openssl rsa -noout -modulus",
        },
        {
            "type": "PrivateKey",
            "start": "-----BEGIN RSA PRIVATE KEY-----",
            "end": "-----END RSA PRIVATE KEY-----",
            "shell": "openssl rsa -noout -modulus",
        },
        {
            "type": "CertificateRequest",
            "start": "-----BEGIN CERTIFICATE REQUEST-----",
            "end": "-----END CERTIFICATE REQUEST-----",
            "shell": "openssl req -noout -subject -modulus",
        },
        {
            "type": "PublicKey",
            "start": "-----BEGIN PUBLIC KEY-----",
            "end": "-----END PUBLIC KEY-----",
            "shell": "openssl rsa -pubin -inform PEM",
        },
    )

    def analyse(
            self,
            iostreams: List[TextIO],
            out: bool = False,
            comments: bool = False,
            under: bool = False,
            prefix: str = "# ",
            indented: bool = True,
            ) -> None:
        # store type of pem we detected
        current_detected_pem_type = None
        # store the lines of pem we detected
        partial_pem_string = ""
        # store pared pam (cer, key, etc.)
        parsed_pem = None

        for iostream in iostreams:
            for line in iostream:
                # if we have an active pem we we need to find its end
                if current_detected_pem_type:
                    partial_pem_string += line
                    if current_detected_pem_type["end"] in line:
                        # deal with the finished pem data
                        try:
                            parsed_pem = self.load_pem(
                                current_detected_pem_type["type"],
                                partial_pem_string)
                        except NotValidPEM:
                            if out:
                                print(partial_pem_string, end="")
                                partial_pem_string = ""

                        # this is the end, reset type
                        current_detected_pem_type = None
                        # we still need parsed_pem and partial_pem_string
                        # reset happens afterwards

                # if we have no active pem we check if there is one
                else:
                    for detectable in self.pem_types:
                        if detectable["start"] in line:
                            # this is the start of a pem
                            current_detected_pem_type = detectable
                            partial_pem_string += line

                # deal with the line itself
                if parsed_pem:
                    parsed_pem.print(
                        out=out,
                        comments=comments,
                        under=under,
                        indented=args.indented
                    )

                    # reset "partial" pem string and PEM object
                    partial_pem_string = ""
                    parsed_pem = None
                    # TODO: optimization idea: do I keep contents of
                    # partial_pem_string in PEM object?

                elif not partial_pem_string:
                    # if there is a partial pem, we do nothing for now
                    # since the analysis is in progress,
                    # but if there is not, treat it like a regular line
                    if out:
                        print(line, end="")

            iostream.close()

            # if there is unfinished pem, just treat it like regular lines
            if partial_pem_string:
                if out:
                    print(partial_pem_string, end="")

    def load_pem(self, pem_type: str, pem_string: str):
        pem_class = eval(pem_type)
        return pem_class(pem_string)


class PEM:
    def __init__(self, pem_string):
        # TODO: softfail if faulty pem data
        self.indent = re.match(WHITESPACE, pem_string).group(0) or ""
        self.pem_string = pem_string
        try:
            self.pem = self.parse_pem()
        except ValueError:
            raise NotValidPEM

        # TODO: Find issuer?

    def print(self,
              out: bool = True,
              comments: bool = True,
              under: bool = False,
              prefix: str = "# ",
              indented: bool = True):
        if comments and not under:
            print(self.comment(prefix, indented))
        if out:
            if indented:
                print(self.pem_string, end="")
            else:
                print(dedent(self.pem_string), end="")
        if comments and under:
            print(self.comment(prefix, indented))

    def maybe_indent(self, comment, indented):
        if indented:
            return f"{self.indent}{comment}"

        return comment

    def parse_pem(self):
        raise NotImplementedError

    def comment(self, prefix: str, indented: bool):
        raise NotImplementedError


class Certificate(PEM):
    def parse_pem(self):
        prepared_pem_string = dedent(self.pem_string).encode()
        return load_pem_x509_certificate(prepared_pem_string)

    def comment(self, prefix: str, indented: bool = True, format=None):
        # TODO: implement different formats
        cn = (self.pem.subject
              .get_attributes_for_oid(NameOID.COMMON_NAME)[0].value or "")
        expiration = self.pem.not_valid_after.strftime("%F")
        short_public_key_hash = sha256(
            str(self.pem.public_key().public_numbers().n).encode()
        ).hexdigest()[:8]

        comment = f"{prefix}{short_public_key_hash}, {cn}, {expiration}"
        return self.maybe_indent(comment, indented)

    def public_key(self):
        return self.pem.public_key()

    def signed_by(self, main_cert):
        return self.__a_signed_b(main_cert, self)

    def signed(self, sub_cert):
        return self.__a_signed_b(self, sub_cert)

    def __a_signed_b(self, issuer_cert, sub_cert):
        try:
            issuer_cert.public_key().verify(
                signature=sub_cert.signature,
                data=sub_cert.tbs_certificate_bytes,
                padding=padding.PKCS1v15(),
                algorithm=sub_cert.signature_hash_algorithm,
            )
        except InvalidSignature:
            return False

        return True


class CertificateRequest(PEM):
    def parse_pem(self):
        prepared_pem_string = dedent(self.pem_string).encode()
        return load_pem_x509_csr(prepared_pem_string)

    def comment(self, prefix: str, indented: bool = True, format=None):
        # TODO: implement different formats
        cn = (self.pem.subject
              .get_attributes_for_oid(NameOID.COMMON_NAME)[0].value or "")
        short_public_key_hash = sha256(
            str(self.pem.public_key().public_numbers().n).encode()
        ).hexdigest()[:8]

        comment = f"{prefix}{short_public_key_hash}, {cn}"
        return self.maybe_indent(comment, indented)


class PrivateKey(PEM):
    def parse_pem(self):
        prepared_pem_string = dedent(self.pem_string).encode()
        return load_pem_private_key(prepared_pem_string, password=None)

    def comment(self, prefix: str, indented: bool = True, format=None):
        # TODO: implement different formats
        short_public_key_hash = sha256(
            str(self.pem.public_key().public_numbers().n).encode()
        ).hexdigest()[:8]

        comment = f"{prefix}{short_public_key_hash}"
        return self.maybe_indent(comment, indented)


class PublicKey(PEM):
    def parse_pem(self):
        prepared_pem_string = dedent(self.pem_string).encode()
        return load_pem_public_key(prepared_pem_string)

    def comment(self, prefix: str, indented: bool = True, format=None):
        # TODO: implement different formats
        short_public_key_hash = sha256(
            str(self.pem.public_numbers().n).encode()
        ).hexdigest()[:8]

        comment = f"{self.indent}{prefix}{short_public_key_hash}"
        return self.maybe_indent(comment, indented)

    def public_key(self):
        return self


def main(args):
    analyser = Analyser()

    # give iostream to analyser
    analyser.analyse(
        args.files,
        out=args.out,
        comments=args.comments,
        under=args.under,
        prefix="# ",
        indented=args.indented
    )


if __name__ == "__main__":
    parser = ArgumentParser()

    parser.add_argument("files", nargs="*",
                        type=FileType("r"), default=[stdin],
                        help="Provide list of files, stdin or - (for stdin)")
    parser.add_argument("--prefix", default="# ",
                        help="Characters with what to prefix the comment")
    parser.add_argument("--under", action="store_true", default=False,
                        help="Insert comment under instead of over")
    parser.add_argument("--noout", dest="out",
                        action="store_false", default=True)
    parser.add_argument("--nocomments", dest="comments",
                        action="store_false",
                        default=True,
                        help="Why do you want that? - Mostly for debugging")
    parser.add_argument("--noindent", dest="indented",
                        action="store_false", default=True)
    # parser.add_argument("--password-file"
    #                     help="Password file for private key")
    # parser.add_argument("--show-signer", action="store_true", default=False)
    # parser.add_argument("--show-issuer", action="store_true", default=False)

    args = parser.parse_args()

    main(args)
