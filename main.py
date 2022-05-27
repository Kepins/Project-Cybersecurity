from crypto_functions import *
import time

import matplotlib.pyplot as plt

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

    # # DSA
    #
    # private_key, public_key = gen_key_dsa(2048)
    #
    # signature = sign_dsa(msg=data, private_key=private_key)
    # verification = verify_dsa(msg=data, signature=signature, public_key=public_key)

    return {'algorithm': ['DES', '3DES', 'Blowfish(128 key)', 'Blowfish(256 key)', 'AES-128', 'AES-192', 'AES-256'],
            'encryption': encryption_times,
            'decryption': decryption_times}


def plot_results(all_times):
    data_sizes = [data_size['data size'] for data_size in all_times]
    alg_times = {}
    for data_size, cur_times in zip(data_sizes, [t['times'] for t in all_times]):
        for alg, enc_time, dec_time in zip(cur_times['algorithm'], cur_times['encryption'], cur_times['decryption']):
            if alg not in alg_times:
                alg_times[alg] = {'encryption': [], 'decryption': []}
            alg_times[alg]['encryption'].append(enc_time)
            alg_times[alg]['decryption'].append(dec_time)


    # convert Bytes to MB
    data_sizes_plot = [ds/10**6 for ds in data_sizes]

    algs_no_plot = ['AES-128', 'AES-192', 'Blowfish(128 key)']

    for alg in alg_times:
        if alg not in algs_no_plot:
            enc_times = alg_times[alg]['encryption']
            dec_times = alg_times[alg]['decryption']
            plt.semilogx(data_sizes_plot, enc_times, label=alg)
            # plt.semilogx(data_sizes_plot, dec_times)
    plt.title('Czasy szyfrowania symetrycznego')
    plt.xlabel('Rozmiar danych [MB]')
    plt.ylabel('Czas szyfrowania[s]')
    plt.legend()
    plt.show()

    aes_algs = ['AES-128', 'AES-192', 'AES-256']

    for alg in alg_times:
        if alg in aes_algs:
            enc_times = alg_times[alg]['encryption']
            dec_times = alg_times[alg]['decryption']
            plt.semilogx(data_sizes_plot, enc_times, label=alg)
            # plt.semilogx(data_sizes_plot, dec_times)
    plt.title('Czasy szyfrowania AES')
    plt.xlabel('Rozmiar danych [MB]')
    plt.ylabel('Czas szyfrowania[s]')
    plt.legend()
    plt.show()


if __name__ == "__main__":

    all_times = []
    data_sizes = [i * 10**6 for i in [1, 10, 50, 100]]
    for data_size in data_sizes:
        data = get_random_bytes(data_size)
        cur_times = get_times_for_functions(data)

        # convert time in ns to s
        cur_times['encryption'] = [ i/(10**9) for i in cur_times['encryption']]
        cur_times['decryption'] = [ i / (10 ** 9) for i in cur_times['decryption']]

        all_times.append({'data size': data_size, 'times': cur_times})

    plot_results(all_times)


