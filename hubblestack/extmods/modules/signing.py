#!/usr/bin/env python
# coding: utf-8

import logging
import hubblestack.utils.signing as HuS

log = logging.getLogger(__name__)

__virtualname__ = 'signing'

def __virtual__():
    return True

def msign(*targets, **kw):
    manifest_fname = kw.get('mfname', 'MANIFEST')
    signature_fname = kw.get('sfname', 'SIGNATURE')
    private_key = kw.get('private_key', HuS.Options.private_key)
    HuS.manifest(targets, mfname=manifest_fname)
    HuS.sign_target(manifest_fname, signature_fname, private_key=private_key)
