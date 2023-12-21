def get_aes(message):
    return message[:128]


def get_nonce(message):
    return message[128:144]


def get_tag(message):
    return message[144:160]


def get_cipher(message):
    return message[160:]
