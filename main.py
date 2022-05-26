from crypto_functions import *
import time


def get_times_for_functions(data):

    encryption_times = []
    decryption_times = []


    # DES

    # encryption
    start_time = time.time_ns()
    encrypted_data, key, iv = encrypt_des_cbc(plaintext=data)
    encryption_times.append(time.time_ns() - start_time)

    # decryption
    start_time = time.time_ns()
    decrypted_data = decrypt_des_cbc(ciphertext=encrypted_data, key=key, iv=iv)
    decryption_times.append(time.time_ns() - start_time)


    # DES3

    # encryption
    start_time = time.time_ns()
    encrypted_data, key, iv = encrypt_des3_cbc(plaintext=data)
    encryption_times.append(time.time_ns() - start_time)

    # decryption
    start_time = time.time_ns()
    decrypted_data = decrypt_des3_cbc(ciphertext=encrypted_data, key=key, iv=iv)
    decryption_times.append(time.time_ns() - start_time)


    # Blowfish 128 bit key

    # encryption
    start_time = time.time_ns()
    encrypted_data, key, iv = encrypt_blowfish_cbc(plaintext=data, key_length=128)
    encryption_times.append(time.time_ns() - start_time)

    # decryption
    start_time = time.time_ns()
    decrypted_data = decrypt_blowfish_cbc(ciphertext=encrypted_data, key=key, iv=iv)
    decryption_times.append(time.time_ns() - start_time)


    # Blowfish 256 bit key

    # encryption
    start_time = time.time_ns()
    encrypted_data, key, iv = encrypt_blowfish_cbc(plaintext=data, key_length=256)
    encryption_times.append(time.time_ns() - start_time)

    # decryption
    start_time = time.time_ns()
    decrypted_data = decrypt_blowfish_cbc(ciphertext=encrypted_data, key=key, iv=iv)
    decryption_times.append(time.time_ns() - start_time)


    # AES 128 bit key

    # encryption
    start_time = time.time_ns()
    encrypted_data, key, iv = encrypt_aes_cbc(plaintext=data, key_length=128)
    encryption_times.append(time.time_ns() - start_time)

    # decryption
    start_time = time.time_ns()
    decrypted_data = decrypt_aes_cbc(ciphertext=encrypted_data, key=key, iv=iv)
    decryption_times.append(time.time_ns() - start_time)

    # AES 182 bit key

    # encryption
    start_time = time.time_ns()
    encrypted_data, key, iv = encrypt_aes_cbc(plaintext=data, key_length=192)
    encryption_times.append(time.time_ns() - start_time)

    # decryption
    start_time = time.time_ns()
    decrypted_data = decrypt_aes_cbc(ciphertext=encrypted_data, key=key, iv=iv)
    decryption_times.append(time.time_ns() - start_time)


    # AES 256 bit key

    # encryption
    start_time = time.time_ns()
    encrypted_data, key, iv = encrypt_aes_cbc(plaintext=data, key_length=256)
    encryption_times.append(time.time_ns() - start_time)

    # decryption
    start_time = time.time_ns()
    decrypted_data = decrypt_aes_cbc(ciphertext=encrypted_data, key=key, iv=iv)
    decryption_times.append(time.time_ns() - start_time)


    # # RSA
    #
    # private_key, public_key = gen_key_rsa(2048)
    #
    # # encryption
    # start_time = time.time_ns()
    # encrypted_data = encrypt_rsa(plaintext=data, public_key=public_key)
    # encryption_times.append(time.time_ns() - start_time)
    #
    # # decryption
    # start_time = time.time_ns()
    # decrypted_data = decrypt_rsa(ciphertext=encrypted_data, private_key=private_key)
    # decryption_times.append(time.time_ns() - start_time)

    # DSA

    private_key, public_key = gen_key_dsa(2048)

    signature = sign_dsa(msg=data, private_key=private_key)
    verification = verify_dsa(msg=data, signature=signature, public_key=public_key)

    return {'algorithm': ['DES', '3DES', 'Blowfish(128 key)', 'Blowfish(256 key)', 'AES-128', 'AES-192', 'AES-256'],
            'encryption': encryption_times,
            'decryption': decryption_times}



if __name__ == "__main__":

    times = []
    data_sizes = [10**i for i in range(5,9)]
    for data_size in data_sizes:
        data = get_random_bytes(data_size)
        cur_times = get_times_for_functions(data)

        # convert time in ns to ms
        cur_times['encryption'] = [ i/(10**6) for i in cur_times['encryption']]
        cur_times['decryption'] = [ i / (10 ** 6) for i in cur_times['decryption']]

        times.append({'data size': data_size, 'times': cur_times})


    print(times)

