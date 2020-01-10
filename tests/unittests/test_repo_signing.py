#!/usr/bin/env python
# coding: utf-8

import os, sys
from pytest import fixture
import hubblestack.utils.signing as sig

@fixture(scope='function')
def no_ppc():
    def nuke():
        for i in ('py', 'pyc'):
            if os.path.isfile('hubblestack/pre_packaged_certificates.{}'.format(i)):
                os.unlink('hubblestack/pre_packaged_certificates.{}'.format(i))
    nuke()
    if 'hubblestack.pre_packaged_certificates' in sys.modules:
        del sys.modules['hubblestack.pre_packaged_certificates']
    yield True
    nuke()

@fixture(scope='session')
def targets():
    _t = [ 'tests/unittests/resources/test-{}.file'.format(i) for i in 'abcd' ]
    for fname in _t:
        if not os.path.isfile(fname):
            with open(fname, 'w') as fh:
                fh.write(fname + ', lol\n')
    return _t

def pc(fname):
    return os.path.join('tests/unittests/resources/pretend-certs', fname)

def opc(fname):
    return os.path.join('tests/unittests/resources/other-pretend-certs', fname)

V = sig.STATUS.VERIFIED
U = sig.STATUS.UNKNOWN
F = sig.STATUS.FAIL

def test_read_certs(no_ppc):
    fname = 'tests/unittests/resources/pretend-certs/bundle.pem'
    fnam2 = 'tests/unittests/resources/pretend-certs/ca-root.crt'

    with open(fname, 'r') as fh:
        dat = fh.read()

    file_read = tuple(sig.read_certs(fname))
    str__read = tuple(sig.read_certs(dat))

    def dc(cobj):
        return sig.ossl.dump_certificate(sig.ossl.FILETYPE_PEM, cobj)

    assert len(file_read) == 2 == len(str__read)
    for i in range(len(file_read)):
        assert dc(file_read[i]) == dc(str__read[i])

    three_certs = tuple(sig.read_certs(fnam2, fname))
    assert len(three_certs) == 3

def test_x509_basics(no_ppc):
    """
    ca-root signed both of the intermediate-1/2 certs

    intermediate-1 signed the public-1.crt
    intermediate-2 signed the public-2.crt

    public-3.crt is signed by an unrelated untrusted ca-root
    """

    # we can verify that both intermediate certs relate to this ca-root
    assert sig.X509(pc('intermediate-1.crt'), pc('ca-root.crt')).authenticate_cert() == V
    assert sig.X509(pc('intermediate-2.crt'), pc('ca-root.crt')).authenticate_cert() == V

    # the intermediate certs can't be verified without the root cert
    # (they can't be verified, but that's all we can really say)
    assert sig.X509(pc('public-1.crt'), pc('intermediate-1.crt')).authenticate_cert() == U
    assert sig.X509(pc('public-1.crt'), pc('intermediate-2.crt')).authenticate_cert() == U

    assert sig.X509(pc('public-2.crt'), pc('intermediate-1.crt')).authenticate_cert() == U
    assert sig.X509(pc('public-2.crt'), pc('intermediate-2.crt')).authenticate_cert() == U

    # with the root cert, the two intermediate certs can verify their child certs only
    # (we can't verify public-1 with intermediate-2, but we can tell it's from
    # the right modulo group, so we can't say the cert is bad either)
    ri1 = (pc('ca-root.crt'), pc('intermediate-1.crt'))
    ri2 = (pc('ca-root.crt'), pc('intermediate-2.crt'))
    assert sig.X509(pc('public-1.crt'), ri1).authenticate_cert() == V
    assert sig.X509(pc('public-1.crt'), ri2).authenticate_cert() == U

    assert sig.X509(pc('public-2.crt'), ri1).authenticate_cert() == U
    assert sig.X509(pc('public-2.crt'), ri2).authenticate_cert() == V

    # with the root cert, the bundle (both intermediates) can verify either child key
    bndl = (pc('ca-root.crt'), pc('bundle.pem'))
    assert sig.X509(pc('public-1.crt'), bndl).authenticate_cert() == V
    assert sig.X509(pc('public-2.crt'), bndl).authenticate_cert() == V

    # public-3 and private-3 are from a totally different ca-root
    # this should give us a real actual FAIL condition
    assert sig.X509(pc('public-3.crt'), bndl).authenticate_cert() == F

def test_msign_and_verify_files(__salt__, targets, no_ppc):
    inverse = {2:1, 1:2}
    sig.Options.ca_crt = (pc('ca-root.crt'), pc('bundle.pem'))

    for i in (1,2):
        # setup key-{i} and sign the repo
        sig.Options.public_crt  = pc('public-{}.crt'.format(i))
        sig.Options.private_key = pc('private-{}.key'.format(i))
        __salt__['signing.msign'](*targets)

        # verify that we trust the files
        res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
        for thing in [ 'MANIFEST' ] + list(targets):
            assert thing in res and res[thing] == V

        # let's mess with one file and see how we do
        with open(targets[-1], 'a') as fh:
            fh.write('hi there!\n')
        res2 = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
        assert targets[-1] in res2 and res2[targets[-1]] == F # we ruined it
        assert targets[0]  in res2 and res2[targets[0]]  == V # still good

        # swap our configs to use the other public key
        # but don't resign the file; uh oh, these aren't signed right now!!
        sig.Options.public_crt  = pc('public-{}.crt'.format(inverse[i]))
        sig.Options.private_key = pc('private-{}.key'.format(inverse[i]))

        res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
        for thing in [ 'MANIFEST' ] + list(targets):
            assert thing in res and res[thing] == F

def test_cert_outside_ca(__salt__, targets, no_ppc):
    # the public/private-3 keypair is not from the same modulo group
    # as the other keys. we should get a FAIL result here
    sig.Options.ca_crt = (pc('ca-root.crt'), pc('bundle.pem'))
    sig.Options.public_crt  = pc('public-3.crt')
    sig.Options.private_key = pc('private-3.key')
    __salt__['signing.msign'](*targets)
    res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
    for thing in [ 'MANIFEST' ] + list(targets):
        assert thing in res and res[thing] == F

def test_no_ca_given(__salt__, targets, no_ppc):
    # the public/private-3 is from some unknown CA
    # ... so if we don't specify any CA, then our result should be unknown
    sig.Options.ca_crt = ''
    sig.Options.public_crt  = pc('public-3.crt')
    sig.Options.private_key = pc('private-3.key')
    __salt__['signing.msign'](*targets)
    res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
    for thing in [ 'MANIFEST' ] + list(targets):
        assert thing in res and res[thing] == U

def test_no_SIGNATURE(__salt__, targets, no_ppc):
    # the public/private-3 is from some unknown CA
    # ... so if we don't specify any CA, then our result should be unknown
    sig.Options.ca_crt = (pc('ca-root.crt'), pc('bundle.pem'))
    sig.Options.public_crt  = pc('public-1.crt')
    sig.Options.private_key = pc('private-1.key')
    __salt__['signing.msign'](*targets)
    os.unlink('SIGNATURE')
    res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
    for thing in [ 'MANIFEST' ] + list(targets):
        assert thing in res and res[thing] == U

def test_no_MANIFEST(__salt__, targets, no_ppc):
    # If we have a SIGNATURE without a MANIFEST, we should fail, because our
    # MANIFEST hash will not match the signed hash -- a sig without manifest is
    # probably a really bad sign and also a rare condition anyway. Also,
    # without the manifest, the most we can say about the rest of the files is
    # UNKNOWN
    sig.Options.ca_crt = (pc('ca-root.crt'), pc('bundle.pem'))
    sig.Options.public_crt  = pc('public-1.crt')
    sig.Options.private_key = pc('private-1.key')
    __salt__['signing.msign'](*targets)
    os.unlink('MANIFEST')
    res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
    assert 'MANIFEST' in res and res['MANIFEST'] == F
    for thing in list(targets):
        assert thing in res and res[thing] == U

def test_no_MANIFEST_or_SIGNATURE(__salt__, targets, no_ppc):
    # if we have a SIGNATURE without a MANIFEST, we should fail
    # because our MANIFEST hash will not match the signed hash
    # (a sig without manifest is probably a really bad sign and also a rare condition anyway)
    sig.Options.ca_crt = (pc('ca-root.crt'), pc('bundle.pem'))
    sig.Options.public_crt  = pc('public-1.crt')
    sig.Options.private_key = pc('private-1.key')
    __salt__['signing.msign'](*targets) # re-sign just to make sure the two files are present
    os.unlink('MANIFEST') # but remove them
    os.unlink('SIGNATURE') # bahleeted
    res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
    len(res) == 0

def pretend_finder(path, saltenv, **kwargs):
    full = rel = os.path.normpath(path)
    if not os.path.isfile(rel):
        full = os.path.join('tests/unittests/resources', rel)
    full = os.path.realpath(full)
    if os.path.isfile(full):
        return {'path': full, 'rel': rel}
    return {'path': '?pf?', 'rel': '?pf?'} # not found for real: ?pf?

wrapped_finder = sig.find_wrapf( # but due to verification trouble, ?wf?
    not_found={'path': '?wf?', 'rel': '?wf?'})(pretend_finder)

def test_fs_find_wrapper_correct_required(__salt__, targets, no_ppc):
    btargets = [ (os.path.basename(x),x) for x in targets ]
    sig.Options.ca_crt = (pc('ca-root.crt'), pc('bundle.pem'))
    sig.Options.require_verify = True

    for i in (1,2):
        sig.Options.public_crt = pc('public-{}.crt'.format(i))
        sig.Options.private_key = pc('private-{}.key'.format(i))
        __salt__['signing.msign'](*targets)

        for btarget,target in btargets:
            full = os.path.realpath(target)
            assert pretend_finder(btarget, 'base').get('path') == full
            assert wrapped_finder(btarget, 'base').get('path') == full

def test_fs_find_wrapper_correct_optional(__salt__, targets, no_ppc):
    btargets = [ (os.path.basename(x),x) for x in targets ]
    sig.Options.ca_crt = (pc('ca-root.crt'), pc('bundle.pem'))
    sig.Options.require_verify = False

    for i in (1,2):
        sig.Options.public_crt = pc('public-{}.crt'.format(i))
        sig.Options.private_key = pc('private-{}.key'.format(i))
        __salt__['signing.msign'](*targets)

        for btarget,target in btargets:
            full = os.path.realpath(target)
            assert pretend_finder(btarget, 'base').get('path') == full
            assert wrapped_finder(btarget, 'base').get('path') == full

def test_fs_find_wrapper_unknown_required(__salt__, targets, no_ppc):
    btargets = [ (os.path.basename(x),x) for x in targets ]
    sig.Options.ca_crt = ''
    sig.Options.require_verify = True

    for i in (1,2):
        sig.Options.public_crt = pc('public-{}.crt'.format(i))
        sig.Options.private_key = pc('private-{}.key'.format(i))
        __salt__['signing.msign'](*targets)

        for btarget,target in btargets:
            full = os.path.realpath(target)
            assert pretend_finder(btarget, 'base').get('path') == full
            assert wrapped_finder(btarget, 'base').get('path') == '?wf?'

def test_fs_find_wrapper_unknown_optional(__salt__, targets, no_ppc):
    btargets = [ (os.path.basename(x),x) for x in targets ]
    sig.Options.ca_crt = ''
    sig.Options.require_verify = False

    for i in (1,2):
        sig.Options.public_crt = pc('public-{}.crt'.format(i))
        sig.Options.private_key = pc('private-{}.key'.format(i))
        __salt__['signing.msign'](*targets)

        for btarget,target in btargets:
            full = os.path.realpath(target)
            assert pretend_finder(btarget, 'base').get('path') == full
            assert wrapped_finder(btarget, 'base').get('path') == full

def test_fs_find_wrapper_incorrect_required(__salt__, targets, no_ppc):
    btargets = [ (os.path.basename(x),x) for x in targets ]
    sig.Options.ca_crt = ''
    sig.Options.require_verify = True

    for i in (1,2):
        sig.Options.public_crt = pc('public-{}.crt'.format(i))
        sig.Options.private_key = pc('private-{}.key'.format(i))
        __salt__['signing.msign'](*targets)
        sig.Options.public_crt = pc('public-{}.crt'.format(3))

        for btarget,target in btargets:
            full = os.path.realpath(target)
            assert pretend_finder(btarget, 'base').get('path') == full
            assert wrapped_finder(btarget, 'base').get('path') == '?wf?'

def test_fs_find_wrapper_incorrect_optional(__salt__, targets, no_ppc):
    btargets = [ (os.path.basename(x),x) for x in targets ]
    sig.Options.ca_crt = ''
    sig.Options.require_verify = False

    for i in (1,2):
        sig.Options.public_crt = pc('public-{}.crt'.format(i))
        sig.Options.private_key = pc('private-{}.key'.format(i))
        __salt__['signing.msign'](*targets)
        sig.Options.public_crt = pc('public-{}.crt'.format(3))

        for btarget,target in btargets:
            full = os.path.realpath(target)
            assert pretend_finder(btarget, 'base').get('path') == full
            assert wrapped_finder(btarget, 'base').get('path') == '?wf?'

def test_bundled_certs(no_ppc):
    # no_ppc ensures there's no pre_packaged_certificates;
    # we then load pretend-certs/public-1, pretend-certs/ca-root and
    # pretend-certs/bundle into x1.
    bndl = (pc('ca-root.crt'), pc('bundle.pem'))
    x1 = sig.X509(pc('public-1.crt'), bndl)

    with open('hubblestack/pre_packaged_certificates.py', 'w') as ofh:
        ofh.write('ca_crt = """\n')
        with open(opc('ca-root.crt')) as ifh:
            for line in ifh:
                ofh.write(line)
        ofh.write('"""\n')
        ofh.flush()

    import hubblestack.pre_packaged_certificates as ppc

    # now there definitely is a pre_packaged_certificates file
    # we lie to X509 and say we want pretend-certs/ca-root.crt
    # but because that's defined in pre_packaged_certificates, it loads that
    # instead.
    bndl = (pc('ca-root.crt'), pc('bundle.pem'))
    x2 = sig.X509(pc('public-1.crt'), bndl)

    ctype = sig.ossl.FILETYPE_PEM

    dc_pub_x1 = sig.ossl.dump_certificate(ctype, x1.public_crt)
    dc_pub_x2 = sig.ossl.dump_certificate(ctype, x2.public_crt)

    dc_ca_x1 = sig.ossl.dump_certificate(ctype, x1.ca_crt[0])
    dc_ca_x2 = sig.ossl.dump_certificate(ctype, x2.ca_crt[0])

    # we said we wanted pc('ca-root.crt'), did we get opc('ca-root.crt') instead?
    assert dc_pub_x1 == dc_pub_x2
    assert dc_ca_x2  in ppc.ca_crt
    assert dc_ca_x1  != dc_ca_x2               # QED

def test_msign_and_verify_signature(__salt__, targets, no_ppc):
    sig.Options.ca_crt = (pc('ca-root.crt'), pc('bundle.pem'))

    sig.Options.public_crt  = pc('public-1.crt')
    sig.Options.private_key = pc('private-1.key')

    __salt__['signing.msign'](*targets)
    res = sig.verify_signature('MANIFEST', 'SIGNATURE',
        public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)

    assert res == sig.STATUS.VERIFIED

    sig.Options.public_crt  = pc('public-1.crt')
    sig.Options.private_key = pc('private-2.key')

    __salt__['signing.msign'](*targets)
    res = sig.verify_signature('MANIFEST', 'SIGNATURE',
        public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)

    assert res == sig.STATUS.FAIL

    sig.Options.public_crt  = pc('public-3.crt')
    sig.Options.private_key = pc('private-3.key')

    __salt__['signing.msign'](*targets)
    res = sig.verify_signature('MANIFEST', 'SIGNATURE',
        public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)

    assert res == sig.STATUS.FAIL


def test_like_a_daemon_with_bundle(__salt__, no_ppc):
    sig.Options.ca_crt = (pc('ca-root.crt'), pc('bundle.pem'))
    sig.Options.public_crt = pc('public-1.crt')
    sig.Options.private_key = pc('private-1.key')

    __salt__['signing.msign']('tests/unittests/conftest.py')
    res = __salt__['signing.verify']('tests/unittests/conftest.py')
    assert len(res) == 2
    for item in res:
        assert res[item] == sig.STATUS.VERIFIED
