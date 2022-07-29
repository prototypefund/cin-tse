from tse.epson import TSE
from datetime import datetime
from tse import TSERole
from tse import exceptions as tse_ex
import logging
import random
from time import sleep
from multiprocessing import Process
logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.DEBUG)

tse = TSE(
        'TSE_FDDA56DAA09F7FAC125E58F45945D1E4AC9ED9133F75C310953B632B42BBBA56',
        '10.0.0.2')

try:
    logging.info('Open the TSE.')
    tse.open()

    # logging.info('Initialize the TSE.')
    # tse.initialize('123456', '12345', '54321')
    #
    # logging.info('Run self test.')
    # tse.run_self_test()

    logging.info('Login Administrator user.')
    tse.login_user('Administrator', TSERole.ADMIN, '12345')

    logging.info('Change secret.')
    tse.register_secret('EPSONKEY')

    logging.info('Logout Administrator user.')
    tse.logout_user('Administrator', TSERole.ADMIN)

    info = tse.info()

    logging.info(
        """
        TSEInfo.public_key: {}
        TSEInfo.model_name: {}
        TSEInfo.state: {}
        TSEInfo.has_valid_time: {}
        TSEInfo.certificate_id: {}
        TSEInfo.certificate_expiration_date: {}
        TSEInfo.unique_id: {}
        TSEInfo.serial_number: {}
        TSEInfo.signature_algorithm: {}
        TSEInfo.signature_counter: {}
        TSEInfo.remaining_signatures: {}
        TSEInfo.max_signatures: {}
        TSEInfo.remaining_signatures: {}
        TSEInfo.max_registered_users: {}
        TSEInfo.max_started_transactions: {}
        TSEInfo.tar_export_size: {}
        TSEInfo.needs_self_test: {}
        TSEInfo.api_version: {}
        """.format(
            info.public_key,
            info.model_name,
            info.state,
            info.has_valid_time,
            info.certificate_id,
            info.certificate_expiration_date,
            info.unique_id,
            info.serial_number,
            info.signature_algorithm,
            info.signature_counter,
            info.remaining_signatures,
            info.max_signatures,
            info.remaining_signatures,
            info.max_registered_users,
            info.max_started_transactions,
            info.tar_export_size,
            info.needs_self_test,
            info.api_version))

    logging.info('Close the TSE.')
    tse.close()

    def process_transactions(user_id):
        tse = TSE(
                'TSE_FDDA56DAA09F7FAC125E58F45945D1E4AC9'
                'ED9133F75C310953B632B42BBBA56',
                '10.0.0.2')

        while True:
            try:
                tse.open()

                logging.info(f'{user_id}: Login Administrator user.')
                tse.login_user('Administrator', TSERole.ADMIN, '12345')

                logging.info(f'{user_id}: Register user.')
                tse.register_user(user_id)

                logging.info(f'{user_id}: Logout Administrator user.')
                tse.logout_user('Administrator', TSERole.ADMIN)

                logging.info(f'{user_id}: Login as TSERole.TIME_ADMIN.')
                tse.login_user(user_id, TSERole.TIME_ADMIN, '54321')

                logging.info(f'{user_id}: Set the time.')
                tse.update_time(user_id, datetime(2022, 7, 11, 23, 59, 59))

                tse.close()
                break
            except tse_ex.TSEInUseError:
                pass

        transactions = []

        while True:
            if random.choice([True, False]):
                while True:
                    try:
                        tse.open()
                        transaction = tse.start_transaction(
                                user_id, 'data', 'type')
                        tse.close()
                        break
                    except tse_ex.TSEInUseError:
                        pass

                logging.info(
                    f'{user_id}: Start new transaction: {transaction.number}')
                transactions.append(transaction)

            if random.choice([True, False]):
                if transactions:
                    while True:
                        try:
                            tse.open()
                            transaction = transactions[
                                    random.randint(0, len(transactions)-1)]
                            tse.update_transaction(
                                user_id, transaction, 'data', 'type')
                            logging.info(
                                f'{user_id}: Update transaction: '
                                f'{transaction.number}')
                            tse.close()
                            break
                        except tse_ex.TSEInUseError:
                            pass

            if random.choice([True, False]):
                if transactions:
                    while True:
                        try:
                            tse.open()
                            transaction = transactions[
                                    random.randint(0, len(transactions)-1)]
                            tse.finish_transaction(
                                user_id, transaction, 'data', 'type')
                            transactions.remove(transaction)
                            logging.info(
                                f'{user_id}: Finish transaction: '
                                f'{transaction.number}')
                            logging.info(
                                f'{user_id}: Open transaction: '
                                f'{len(transactions)}')
                            tse.close()
                            break
                        except tse_ex.TSEInUseError:
                            pass

            sleep(random.uniform(0.5, 2))

    process_1 = Process(target=process_transactions, args=('pos1',))
    process_2 = Process(target=process_transactions, args=('pos2',))
    process_3 = Process(target=process_transactions, args=('pos3',))
    process_4 = Process(target=process_transactions, args=('pos4',))
    process_1.start()
    process_2.start()
    process_3.start()
    process_4.start()

    while True:
        pass

except Exception as e:
    logging.exception(e)
    logging.info('The process_1 closed.')

except KeyboardInterrupt:
    process_1.terminate()
    process_2.terminate()
    process_3.terminate()
    process_4.terminate()
