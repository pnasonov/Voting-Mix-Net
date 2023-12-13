import random
import secrets

from voter import Voter
from crypto_utils import (
    generate_rsa_keys,
    generate_elgamal_keys,
    encrypt_message,
    decrypt_message,
    count_votes
)


def voting() -> None:
    # Створення виборців і присвоєння їм RSA та Elgamal ключів
    voter_a = Voter(*generate_rsa_keys(), *generate_elgamal_keys())
    voter_b = Voter(*generate_rsa_keys(), *generate_elgamal_keys())
    voter_c = Voter(*generate_rsa_keys(), *generate_elgamal_keys())
    voter_d = Voter(*generate_rsa_keys(), *generate_elgamal_keys())

    voters = [voter_a, voter_b, voter_c, voter_d]

    # Генерація випадкових рядків для бюлетенів
    for voter in voters:
        voter.random_lines = [
            secrets.token_hex(16),
            secrets.token_hex(16),
            secrets.token_hex(16),
            secrets.token_hex(16),
            secrets.token_hex(16),
        ]

    # Генерація бюлетенів з випадковими рядками
    for voter in voters:
        voter.choice = str(random.randint(0, 1)) + voter.random_lines[0]

    # Шифрування відкритим ключем D виборця
    for voter in voters:
        voter.en_d = encrypt_message(
            voter.choice.encode(), voter_d.public_key
        )

    # Шифрування відкритим ключем C виборця
    for voter in voters:
        voter.en_c = encrypt_message(voter.en_d, voter_c.public_key)

    # Шифрування відкритим ключем B виборця
    for voter in voters:
        voter.en_b = encrypt_message(voter.en_c, voter_b.public_key)

    # Шифрування відкритим ключем A виборця  (FcB(FcC(FcD(Ev, Rs1))))
    for voter in voters:
        voter.en_a = encrypt_message(voter.en_b, voter_a.public_key)

    # Додавання нового випадкового рядка та шифрування ключем D виборця
    for voter in voters:
        voter.en_d_rand_line = encrypt_message(
            voter.en_a + voter.random_lines[1].encode(),
            voter_d.public_key
        )

    # Додавання нового випадкового рядка та шифрування ключем C виборця
    for voter in voters:
        voter.en_c_rand_line = encrypt_message(
            voter.en_d_rand_line + voter.random_lines[2].encode(),
            voter_c.public_key
        )

    # Додавання нового випадкового рядка та шифрування ключем B виборця
    for voter in voters:
        voter.en_b_rand_line = encrypt_message(
            voter.en_c_rand_line + voter.random_lines[3].encode(),
            voter_b.public_key
        )

    # Додавання нового випадкового рядка та шифрування ключем A виборця
    for voter in voters:
        voter.en_a_rand_line = encrypt_message(
            voter.en_b_rand_line + voter.random_lines[4].encode(),
            voter_a.public_key
        )

    # НАСТУПНИЙ ЕТАП Е-ГОЛОСУВАННЯ
    # Перевірка, що кількість бюлетенів співпадає з кількістю виборців
    # shuffle

    # Bиборець A розшифровує своїм ключем всі бюлетені
    for voter in voters:
        voter_a.decrypted.append(decrypt_message(
            voter.en_a_rand_line, voter_a.private_key
        ))

    # Bиборець A шукає свій випадковий рядок серед всіх бюлетенів
    for decrypted in voter_a.decrypted:
        if decrypted[-32:].decode() == voter_a.random_lines[4]:
            print("Рядок voter_a.random_line було знайдено "
                  "серед бюлетенів.")

    # Bиборець B розшифровує своїм ключем всі бюлетені
    for i in range(4):
        voter_b.decrypted.append(decrypt_message(
            voter_a.decrypted[i][:-32], voter_b.private_key
        ))

    # Bиборець B шукає свій випадковий рядок серед всіх бюлетенів
    for decrypted in voter_b.decrypted:
        if decrypted[-32:].decode() == voter_b.random_lines[3]:
            print("Рядок voter_b.random_line було знайдено "
                  "серед бюлетенів.")

    # Bиборець C розшифровує своїм ключем всі бюлетені
    for i in range(4):
        voter_c.decrypted.append(decrypt_message(
            voter_b.decrypted[i][:-32], voter_c.private_key
        ))

    # Bиборець C шукає свій випадковий рядок серед всіх бюлетенів
    for decrypted in voter_c.decrypted:
        if decrypted[-32:].decode() == voter_c.random_lines[2]:
            print("Рядок voter_c.random_line було знайдено "
                  "серед бюлетенів.")

    # Bиборець D розшифровує своїм ключем всі бюлетені
    for i in range(4):
        voter_d.decrypted.append(decrypt_message(
            voter_c.decrypted[i][:-32], voter_d.private_key
        ))

    # Bиборець D шукає свій випадковий рядок серед всіх бюлетенів
    for decrypted in voter_d.decrypted:
        if decrypted[-32:].decode() == voter_d.random_lines[1]:
            print("Рядок voter_d.random_line було знайдено "
                  "серед бюлетенів.\n")

    #########

    # виборець A розшифровує всі бюлетені своїм приватним ключем
    for i in range(4):
        voter_a.decrypted[i] = decrypt_message(
            voter_d.decrypted[i][:-32],
            voter_a.private_key
        )

    # виборець A звіряє криптограми
    for j in range(4):
        if voter_a.decrypted[j] == voter_a.en_b:
            print("Криптограми співпадають. Бюлетень виборця A на місці.")

    # виборець A підписує всі бюлетені
    for i in range(4):
        voter_a.subscribed.append(voter_a.sign_message(
            voter_a.decrypted[i], voter_a.private_elgamal
        ))

    # Перевірка підпису
    for j in range(4):
        if voter_a.verify_signature(
                voter_b.en_b,
                voter_a.subscribed[j],
                voter_a.public_elgamal
        ):
            print("Підпис виборця A підтверджено!")

    # виборець B розшифровує всі бюлетені своїм приватним ключем
    for i in range(4):
        voter_b.decrypted[i] = decrypt_message(
            voter_a.decrypted[i],
            voter_b.private_key
        )

    # виборець B звіряє криптограми
    for j in range(4):
        if voter_b.decrypted[j] == voter_b.en_c:
            print("Криптограми співпадають. Бюлетень виборця B на місці.")

    # виборець B підписує всі бюлетені
    for i in range(4):
        voter_b.subscribed.append(voter_b.sign_message(
            voter_b.decrypted[i], voter_b.private_elgamal
        ))

    # Перевірка підпису
    for j in range(4):
        if voter_b.verify_signature(
                voter_c.en_c,
                voter_b.subscribed[j],
                voter_b.public_elgamal
        ):
            print("Підпис виборця B підтверджено!")

    # виборець C розшифровує всі бюлетені своїм приватним ключем
    for i in range(4):
        voter_c.decrypted[i] = decrypt_message(
            voter_b.decrypted[i],
            voter_c.private_key
        )

    # виборець C звіряє криптограми
    for j in range(4):
        if voter_c.decrypted[j] == voter_c.en_d:
            print("Криптограми співпадають. Бюлетень виборця C на місці.")

    # виборець C підписує всі бюлетені
    for i in range(4):
        voter_c.subscribed.append(voter_c.sign_message(
            voter_c.decrypted[i], voter_c.private_elgamal
        ))

    # Перевірка підпису
    for j in range(4):
        if voter_c.verify_signature(
                voter_d.en_d,
                voter_c.subscribed[j],
                voter_c.public_elgamal
        ):
            print("Підпис виборця C підтверджено!")

    # виборець D розшифровує всі бюлетені своїм приватним ключем
    for i in range(4):
        voter_d.decrypted[i] = decrypt_message(
            voter_c.decrypted[i],
            voter_d.private_key
        )

    # виборець D звіряє криптограми
    for j in range(4):
        if voter_d.decrypted[j].decode() == voter_d.choice:
            print("Криптограми співпадають. Бюлетень виборця D на місці.")

    # виборець D підписує всі бюлетені
    for i in range(4):
        voter_d.subscribed.append(voter_d.sign_message(
            voter_d.decrypted[i], voter_d.private_elgamal
        ))

    # перевірка всіх підписів
    letters = ("A", "B", "C", "D")
    for letter in letters:
        for j in range(4):
            if voter_d.verify_signature(
                    voters[j].choice.encode(),
                    voter_d.subscribed[j],
                    voter_d.public_elgamal
            ):
                print(f"Підпис виборця D підтверджено виборцем {letter}.")
                break

    # перевірка всіх бюлетенів
    count = 0
    for i, voter in enumerate(voters):

        for j in range(4):
            if voter_d.decrypted[j].decode() == voter.choice:
                count += 1
                break
    if count == 4:
        print("\nБюлетні всіх виборців на місці.\n")
    else:
        print("Кількість бюлетнів не відповідає кількості виборців")
        return

    # Підрахунок
    for i, voter in enumerate(voters):
        for j in range(4):
            voter.result.append(voter_d.decrypted[j].decode()[:-32])

    for i, voter in enumerate(voters):
        print(f"Голоси виборця {letters[i]}: "
              f"{', '.join([voter.result[j] for j in range(4)])}")

    votes = [int(voter_d.result[0]),
             int(voter_d.result[1]),
             int(voter_d.result[2]),
             int(voter_d.result[3])]
    winner = count_votes(votes)
    print("\nПереміг: ", winner)


voting()
