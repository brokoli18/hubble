# coding: utf-8

import os
import getpass
import logging
import re
import json
import inspect

from collections import OrderedDict, namedtuple

# In any case, pycrypto won't do the job. The below requires pycryptodome.
# (M2Crypto is the other choice; but the docs are weaker, mostly non-existent.)

from Crypto.IO import PEM
from Crypto.Util import asn1
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import OpenSSL.crypto as ossl

MANIFEST_RE = re.compile(r'^\s*(?P<digest>[0-9a-fA-F]+)\s+(?P<fname>.+)$')
log = logging.getLogger(__name__)

class STATUS:
    OK = 'ok'
    FAIL = 'fail'
    VERIFIED = 'verified'
    UNKNOWN = 'unknown'


class Options(object):
    class defaults:
        require_verify = False
        ca_crt = '/etc/hubble/sign/ca-root.crt'
        public_crt = '/etc/hubble/sign/public.crt'
        private_key = '/etc/hubble/sign/private.key'

    def __getattribute__(self, name):
        """ If the option exists in the default pseudo meta class
            Try to find the option with config.get under repo_signing.
            Failing that, return the default from the pseudo meta class.
            If the option name isn't in the defaults, raise the exception.
        """
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            pass
        try:
            default = getattr(self.defaults, name)
            return __salt__['config.get']('repo_signing:{}'.format(name), default)
      # except NameError:
      #     # __salt__ isn't defined: return the default?
      #     # should we just raise an exception cuz this was called too early??
      #     return default
        except AttributeError:
            raise
Options = Options()


class X509:
    PEMData = namedtuple('PEMData', ['cert','marker','decrypted'])
    CrtData = namedtuple('CrtData', ['cert','algo','sig'])
    SigData = namedtuple('SigData', ['nonzero_bits','dat', 'algo'])

    def __init__(self, public_crt, ca_crt):
        self.public_crt = public_crt
        self.ca_crt = ca_crt
        with open(ca_crt, 'r') as fh:
            self.ca_raw = fh.read()
        with open(public_crt, 'r') as fh:
            self.crt_raw = fh.read()

        self.ca = ossl.load_certificate(ossl.FILETYPE_PEM, self.ca_raw)
        ossl_crt = ossl.load_certificate(ossl.FILETYPE_PEM, self.crt_raw)
        self.pdat = self.PEMData(*PEM.decode(self.crt_raw))
        self.cdat = self.CrtData(*asn1.DerSequence().decode(self.pdat.cert))
        _sig = asn1.DerObject().decode(self.cdat.sig).payload
        self.sig = self.SigData(_sig[0], _sig[1:], ossl_crt.get_signature_algorithm().decode())
        self.crt = RSA.importKey(self.pdat.cert)
        self.verifier = PKCS1_v1_5.new(self.crt)

    def verify_cert(self):
        if self.sig.nonzero_bits != 0 and self.sig.nonzero_bits != '\x00': # py3 vs py2
            log.error('The CA cert (%s) may not approve of this certificate (%s): unusual padding bits',
                self.ca_crt, self.public_crt)
            return STATUS.UNKNOWN
        try:
            ossl.verify(self.ca, str(self.sig.dat), str(self.cdat.cert), str(self.sig.algo))
            return STATUS.VERIFIED
        except ossl.Error:
            # the error ossl raises is not useful (apparently)
            log.error('The CA cert (%s) does not seem to approve of this certificate (%s)')
        return STATUS.UNKNOWN


def jsonify(obj, indent=2):
    return json.dumps(obj, indent=indent)

def normalize_path(path, trunc=None):
    """ attempt to translate /home/./jettero////files/.bashrc
        to /home/jettero/files/.bashrc; optionally truncating
        the path if it starts with the given trunc kwarg string.
    """
    norm = os.path.normpath(path)
    if trunc:
        if norm.startswith(os.path.sep + trunc + os.path.sep):
            norm = norm[len(trunc)+2:]
        elif norm.startswith(trunc + os.path.sep):
            norm = norm[len(trunc)+1:]
        elif norm.startswith(os.path.sep + trunc):
            norm = norm[len(trunc)+1:]
        elif norm.startswith(trunc):
            norm = norm[len(trunc):]
    # log.debug("normalize_path(%s) --> %s", path, norm)
    return norm

def hash_target(fname, obj_mode=False):
    """ read in a file (fname) and either return the hex digest
        (obj_mode=False) or a sha256 object pre-populated with the contents of
        the file.
    """
    s256 = SHA256.new()
    if os.path.isfile(fname):
        with open(fname, 'rb') as fh:
            r = fh.read(1024)
            while r:
                s256.update(r)
                r = fh.read(1024)
    if obj_mode:
        return s256
    hd = s256.hexdigest()
    log.debug('hashed %s: %s', fname, hd)
    return hd

def descend_targets(targets, cb):
    for fname in targets:
        if os.path.isfile(fname):
            cb(fname)
        if os.path.isdir(fname):
            for dirpath, dirnames, filenames in os.walk(fname):
                for fname in filenames:
                    fname_ = os.path.join(dirpath, fname)
                    cb(fname_)

def manifest(targets, mfname='MANIFEST'):
    with open(mfname, 'w') as mfh:
        def append_hash(fname):
            fname = normalize_path(fname)
            digest = hash_target(fname)
            mfh.write('{} {}\n'.format(digest, fname))
            log.debug('wrote %s %s to %s', digest, fname, mfname)
        descend_targets(targets, append_hash)

def sign_target(fname, ofname, private_key='private.key', **kw):
    with open(private_key, 'r') as fh:
        private_key = RSA.importKey(fh.read())
    signer = PKCS1_v1_5.new(private_key)
    sig = signer.sign(hash_target(fname, obj_mode=True))
    with open(ofname, 'w') as fh:
        log.debug('writing signature to %s', ofname)
        fh.write(PEM.encode(sig, 'Detached Signature of {}'.format(fname)))
        fh.write('\n')

def verify_signature(fname, sfname, public_crt='public.crt', ca_crt='ca-root.crt', **kw):
    """
        Given the fname, sfname public_crt and ca_crt:

        return STATUS.FAIL if the signature doesn't match
        return STATUS.UNKNOWN if the certificate signature can't be verified with the ca cert
        return STATUS.VERIFIED if both the signature and the CA sig match
    """
    x509 = X509(public_crt, ca_crt)
    ca_status = x509.verify_cert()
    try:
        with open(sfname, 'r') as fh:
            signature,_,_ = PEM.decode(fh.read()) # also returns header and decrypted-status
    except IOError:
        log.error('failed to find %s for %s', sfname, fname)
        return STATUS.UNKNOWN
    if x509.verifier.verify(hash_target(fname, obj_mode=True), signature):
        return ca_status
    log.error('%s failed signature check (%s)', fname, sfname)
    return STATUS.FAIL

def iterate_manifest(mfname):
    with open(mfname, 'r') as fh:
        for line in fh.readlines():
            matched = MANIFEST_RE.match(line)
            if matched:
                _,manifested_fname = matched.groups()
                manifested_fname = normalize_path(manifested_fname)
                yield manifested_fname

def verify_files(targets, mfname='MANIFEST', sfname='SIGNATURE', public_crt='public.crt', ca_crt='ca-root.crt'):
    """ given a list of `targets`, a MANIFEST, and a SIGNATURE file:

        1. Check the signature of the manifest, mark the 'MANIFEST' item of the return as:
             STATUS.FAIL if the signature doesn't match
             STATUS.UNKNOWN if the certificate signature can't be verified with the ca cert
             STATUS.VERIFIED if both the signature and the CA sig match
        2. mark all targets as STATUS.UNKNOWN
        3. check the digest of each target against the manifest, mark each file as
             STATUS.FAIL if the digest doesn't match
             STATUS.*, the status of the MANIFEST file above

        return a mapping from the input target list to the status values (a dict of filename: status)
    """
    ret = OrderedDict()
    ret[mfname] = verify_signature(mfname, sfname=sfname, public_crt=public_crt, ca_crt=ca_crt)
    # ret[mfname] is the strongest claim we can make about the files we're
    # verifiying if they match their hash in the manifest, the best we can say
    # is whatever is the status of the manifest iteslf.

    mf_dir, _ = os.path.split(mfname)
    sf_dir, _ = os.path.split(sfname)

    if mf_dir and mf_dir == sf_dir:
        trunc = mf_dir + '/'
    else:
        trunc = None

    # prepopulate digests with STATUS.UNKNOWN, skip things that shouldn't be
    # digested (MANIFEST, SIGNATURE, etc) and build a database mapping
    # normalized names back to given target names.
    xlate = dict()
    digests = OrderedDict()
    if not targets:
        targets = list(iterate_manifest(mfname))
    for otarget in targets:
        target = normalize_path(otarget, trunc=trunc)
        if otarget != target:
            xlate[target] = otarget
        if target in digests or target in (mfname, sfname):
            continue
        digests[target] = STATUS.UNKNOWN
    # populate digests with the hashes from the MANIFEST
    if os.path.isfile(mfname):
        with open(mfname, 'r') as fh:
            for line in fh.readlines():
                matched = MANIFEST_RE.match(line)
                if matched:
                    digest,manifested_fname = matched.groups()
                    manifested_fname = normalize_path(manifested_fname)
                    if manifested_fname in digests:
                        digests[manifested_fname] = digest
    # compare actual digests of files (if they exist) to the manifested digests
    for vfname in digests:
        digest = digests[vfname]
        if digest == STATUS.UNKNOWN:
            # digests[vfname] is either UNKNOWN (from the targets population)
            # or it's a digest from the MANIFEST. If UNKNOWN, we have nothing to compare
            # so we return UNKNOWN
            ret[vfname] = STATUS.UNKNOWN
        elif digest == hash_target( os.path.join(trunc, vfname) ):
            # Cool, the digest matches, but rather than mark STATUS.VERIFIED,
            # we mark it with the same status as the MANIFEST it self --
            # presumably it's signed (STATUS.VERIFIED); but perhaps it's only
            # UNKNOWN or even FAIL.
            ret[vfname] = ret[mfname]
        else:
            # We do have a MANIFEST entry and it doesn't match: FAIL with or
            # without a matching SIGNATURE
            ret[vfname] = STATUS.FAIL
    # fix any normalized names so the caller gets back their specified targets
    for k,v in xlate.iteritems():
        ret[v] = ret.pop(k)
    return ret


#### wrappers:
def find_wrapf(not_found={'path': '', 'rel': ''}, real_path='path'):
    def wrapper(find_file_f):
        def _p(fnd):
            return fnd.get(REAL_PATH, fnd.get('path', ''))

        def inner(path, saltenv, *a, **kw):
            f_mani = find_file_f('MANIFEST', saltenv, *a, **kw )
            f_sign = find_file_f('SIGNATURE', saltenv, *a, **kw )
            f_path = find_file_f(path, saltenv, *a, **kw)
            real_path = _p(f_path)
            mani_path = _p(f_mani)
            sign_path = _p(f_sign)
            log.debug('path=%s rpath=%s manifest=%s signature=%s',
                path, real_path, mani_path, sign_path)
            verify_res = verify_files([real_path],
                mfname=mani_path, sfname=sign_path,
                public_crt=Options.public_crt, ca_crt=Options.ca_crt)
            log.debug('verify: %s', dict(**verify_res))
            vrg = verify_res.get(real_path, STATUS.UNKNOWN)
            if vrg == STATUS.VERIFIED:
                return f_path
            if vrg == STATUS.UNKNOWN and not Options.require_verify:
                return f_path
            return dict(**not_found)
        return inner
    return wrapper
