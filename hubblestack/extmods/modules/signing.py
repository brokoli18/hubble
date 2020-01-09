#!/usr/bin/env python
# coding: utf-8

import logging
import hubblestack.utils.signing as HuS

log = logging.getLogger(__name__)

__virtualname__ = 'signing'

def __virtual__():
    return True

def msign(*targets, mfname='MANIFEST', sfname='SIGNATURE', private_key=Options.private_key):
    """
    Sign a files and directories. Will overwrite whatever's already in MANIFEST.
    Arguments: files and/or directories
    KW Arguments:
        mfname :- the MANIFEST filename (default ./MANIFEST)
        sfname :- the SIGNATURE filename (default ./SIGNATURE)
        private_key :- the private key to use for the signature (default
            /etc/hubble/sign/private.key)
    """
    HuS.manifest(targets, mfname=mfname)
    HuS.sign_target(mfname, sfname, private_key=private_key)

# def verify_files(*targets, mfname='MANIFEST', sfname='SIGNATURE',
#     public_crt=Options.public_crt, ca_crt=Options.ca_crt):
#     """
#     Verify files
#     Arguments: files and/or directories
#     KW Arguments:
#         mfname :- the MANIFEST filename (default ./MANIFEST)
#         sfname :- the SIGNATURE filename (default ./SIGNATURE)

#         public_crt :- the signing key (default: /etc/hubble/sign/public.crt)
#         ca_crt :- the trust chain for the public_crt (default: /etc/hubble/sign/ca-root.crt)
#                   can optionally be a list of cert files; in which case, the
#                   first file is trusted, and additional files are assumed to be
#                   intermediates and are only trusted if a trust path can be
#                   found.
#     """
#     HuS.verify_files(targets, mfname=mfname, sfname=sfname, public_crt=public_crt, ca_crt=ca_crt)
