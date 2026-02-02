from server.merkle import verify_inclusion


def test_fake_inclusion_proof():

    fake_leaf = b"fake"
    fake_proof = []
    fake_root = b"\x00" *32


    result = verify_inclusion(fake_leaf, fake_proof, fake_root)

    assert result is False 