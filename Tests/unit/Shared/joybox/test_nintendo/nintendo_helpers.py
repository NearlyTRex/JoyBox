TOOL_PATHS = {
    "NDecrypt": "/tools/ndecrypt",
    "CtrMakeRom": "/tools/makerom",
    "CtrTool": "/tools/ctrtool",
    "3DSRomTool": "/tools/3dsromtool",
    "CDecrypt": "/tools/cdecrypt",
    "HacTool": "/tools/hactool",
    "XCITrimmer": "/tools/xcitrimmer.py",
    "PythonVenvPython": "/tools/venv/python",
}

VALID_ID = "F6F389D41D6BC0BDD6BD928C526AE556"


def read_dat(path):
    with open(str(path), "rb") as handle:
        return handle.read()


WAD_TITLE_ID = "0001000157414c45"
WAD_CONTENT = b"channel content"


def _certificate(issuer, child_name):
    from libWiiPy.title.cert import Certificate, CertificateKeyType, CertificateType
    cert = Certificate()
    cert.type = CertificateType.RSA_2048
    cert.signature = bytes(0x100)
    cert.issuer = issuer
    cert.pub_key_type = CertificateKeyType.RSA_2048
    cert.child_name = child_name
    cert.pub_key_id = 0
    cert.pub_key_modulus = 1
    cert.pub_key_exponent = 0x10001
    return cert


def build_wad(path):
    # A minimal unsigned WAD holding one normal content; Title.add_content
    # cannot start from an empty title, so the content is encrypted here
    import hashlib
    from libWiiPy.title import Title
    from libWiiPy.title.crypto import encrypt_content
    title_id = bytes.fromhex(WAD_TITLE_ID)
    tmd = bytearray(0x1E4)
    tmd[0x0:0x4] = b"\x00\x01\x00\x01"
    tmd[0x18C:0x194] = title_id
    ticket = bytearray(0x2A4)
    ticket[0x0:0x4] = b"\x00\x01\x00\x01"
    ticket[0x1DC:0x1E4] = title_id
    title = Title()
    title.cert_chain.ca_cert = _certificate("Root", "CA00000001")
    title.cert_chain.tmd_cert = _certificate("Root-CA00000001", "CP00000004")
    title.cert_chain.ticket_cert = _certificate("Root-CA00000001", "XS00000003")
    title.load_tmd(bytes(tmd))
    title.load_ticket(bytes(ticket))
    title.load_content_records()
    title.add_enc_content(
        encrypt_content(WAD_CONTENT, title.ticket.get_title_key(), 0), 0, 0, 1,
        len(WAD_CONTENT), hashlib.sha1(WAD_CONTENT).hexdigest().encode())
    with open(str(path), "wb") as handle:
        handle.write(title.dump_wad())
    return str(path)
