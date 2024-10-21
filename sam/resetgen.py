import json

def main():
    rid = int(input('Enter the account RID: '), 16)

    with open('reset.reg', 'w+') as f:
        reset_data = {
            'version': 1,
            'questions': [
                {
                    'question': 'Question 1',
                    'answer': 'Answer 1'
                },
                {
                    'question': 'Question 2',
                    'answer': 'Answer 2'
                },
                {
                    'question': 'Question 3',
                    'answer': 'Answer 3'
                },
            ]
        }

        x = [f'{byte:02x}' for byte in list(json.dumps(reset_data).encode('utf-16-le'))]
        s = ','.join(x)

        f.write('Windows Registry Editor Version 5.00\n\n')
        f.write(f'[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\{rid:08X}]\n')
        f.write(f'"ResetData"=hex:{s}')

        print('Data written to reset.reg!')


if __name__ == '__main__':
    main()