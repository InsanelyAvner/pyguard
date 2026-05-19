import random

FLAG = "REDACTED"
secret_number = random.randint(0, 10**12)

try:
    guess = int(input("Guess the number between 0 and 10^12: "))
    if guess == secret_number:
        print(f"Congratulations! Here is your flag: {FLAG}")
    else:
        print(f"Incorrect. The number was {secret_number}.")
except ValueError:
    print("Invalid input. Please enter an integer.")