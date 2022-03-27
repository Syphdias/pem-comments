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
# (not serial, not subject, not signature(s), not timest, etc.)
#
# example comments:
# # CN=*.example.com example.com 2022-01-11 alice1 by bob1
from typing import TextIO, List
from sys import stdin
from argparse import ArgumentParser, FileType
from textwrap import dedent
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
    infos_about_detectable_pems = (
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
        # store infos about of pem we detected
        current_detected_pem_info = None
        # store the lines of pem we detected
        partial_pem_string = ""
        # store pared pam (cer, key, etc.)
        parsed_pem = None

        # fill results
        results = Results()
        for iostream in iostreams:
            for line in iostream:
                # if we have an active pem we we need to find its end
                if current_detected_pem_info:
                    partial_pem_string += line
                    if current_detected_pem_info["end"] in line:
                        # deal with the finished pem data
                        try:
                            parsed_pem = self.load_pem(
                                current_detected_pem_info["type"],
                                partial_pem_string)
                            results.append(parsed_pem)
                        except NotValidPEM:
                            results.append(partial_pem_string)

                        # Reset current PEM parsing
                        current_detected_pem_info = None
                        parsed_pem = None
                        partial_pem_string = ""

                # if we have no active pem we check if there is one
                else:
                    for detectable_pem in self.infos_about_detectable_pems:
                        if detectable_pem["start"] in line:
                            # this is the start of a pem
                            current_detected_pem_info = detectable_pem
                            partial_pem_string += line
                    if not current_detected_pem_info:
                        # There was no start of PEM
                        results.append(line)

                # if wanted and possible, print the currently printable
                results.consume(
                    out=out,
                    comments=comments,
                    under=under,
                    indented=args.indented,
                )

            iostream.close()

            # if there is unfinished pem, just treat it like regular lines
            if partial_pem_string:
                results.append(partial_pem_string)
                # Reset current PEM parsing
                current_detected_pem_info = None
                parsed_pem = None
                partial_pem_string = ""

            # TODO: Should I results.consume here to finish all of one iostream?

        # We are done with all input
        # We can not analyse everything left and print
        results.consume(
            delay=False,
            out=out,
            comments=comments,
            under=under,
            indented=args.indented,
        )

    def load_pem(self, pem_type: str, pem_string: str):
        pem_class = eval(pem_type)
        return pem_class(pem_string)


class Results(list):
    """This class collects the parsed and unparsed contents"""
    def __init__(self, *args):
        super().__init__(*args)
        self.certs = set()

    def consume(self, delay: bool = False, out: bool = True, **print_options) -> None:
        """Print all elements up to this point in Result

        Normal lines will be printed as is, PEMs use the print method with
        given options.
        """
        # Do not consume
        if delay:
            return

        while self:
            element = self.pop(0)
            if isinstance(element, PEM):
                element.print(out=out, **print_options)
            else:
                if out:
                    print(element, end="")

    def append(self, __object) -> None:
        appended = super().append(__object)

        if isinstance(__object, Certificate):
            self.certs.add(__object)

        # self.__analyse_certs()

        return appended

    def __analyse_certs(self):
        raise NotImplementedError


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
                signature=sub_cert.pem.signature,
                data=sub_cert.pem.tbs_certificate_bytes,
                padding=padding.PKCS1v15(),
                algorithm=sub_cert.pem.signature_hash_algorithm,
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
