#!/usr/bin/env python
# coding: utf-8

import logging
import hubblestack.utils.signing as HuS

log = logging.getLogger(__name__)

__virtualname__ = 'signing'

def __virtual__():
    return True

def msign(*targets, **kw):
    """
    Sign a files and directories. Will overwrite whatever's already in MANIFEST.
    Arguments: files and/or directories
    KW Arguments:
        mfname :- the MANIFEST filename (default ./MANIFEST)
        sfname :- the SIGNATURE filename (default ./SIGNATURE)
        private_key :- the private key to use for the signature (default
            /etc/hubble/sign/private.key)
    """
    manifest_fname = kw.get('mfname', 'MANIFEST')
    signature_fname = kw.get('sfname', 'SIGNATURE')
    private_key = kw.get('private_key', HuS.Options.private_key)
    HuS.manifest(targets, mfname=manifest_fname)
    HuS.sign_target(manifest_fname, signature_fname, private_key=private_key)
