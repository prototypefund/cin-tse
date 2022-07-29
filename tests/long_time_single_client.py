from tse.epson import TSE
from datetime import datetime
from tse import TSERole
import logging
import random
from time import sleep
logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.DEBUG)

tse = TSE(
        'TSE_FDDA56DAA09F7FAC125E58F45945D1E4AC9ED9133F75C310953B632B42BBBA56',
        '10.0.0.2')

try:
    logging.info('Open the TSE.')
    tse.open()

    logging.info('Initialize the TSE.')
    tse.initialize('123456', '12345', '54321')

    logging.info('Run self test.')
    tse.run_self_test()

    logging.info('Login Administrator user.')
    tse.login_user('Administrator', TSERole.ADMIN, '12345')

    logging.info('Change secret.')
    tse.register_secret('EPSONKEY')

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

    logging.info('Register user "pos".')
    tse.register_user('pos')

    logging.info('Logout Administrator user.')
    tse.logout_user('Administrator', TSERole.ADMIN)

    logging.info('Login user "pos" as TSERole.TIME_ADMIN.')
    tse.login_user('pos', TSERole.TIME_ADMIN, '54321')

    logging.info('Set the time.')
    tse.update_time('pos', datetime(2022, 7, 11, 23, 59, 59))

    transactions = []

    while True:
        if random.choice([True, False]):
            transaction = tse.start_transaction('pos', 'data', 'type')
            logging.info(f'Start new transaction: {transaction.number}')
            transactions.append(transaction)

        if random.choice([True, False]):
            if transactions:
                transaction = transactions[
                        random.randint(0, len(transactions)-1)]
                tse.update_transaction('pos', transaction, 'data', 'type')
                logging.info(f'Update transaction: {transaction.number}')

        if random.choice([True, False]):
            if transactions:
                transaction = transactions[
                        random.randint(0, len(transactions)-1)]
                tse.finish_transaction('pos', transaction, 'data', 'type')
                transactions.remove(transaction)
                logging.info(f'Finish transaction: {transaction.number}')
                logging.info(f'Open transaction: {len(transactions)}')

        sleep(random.uniform(0.5, 1.5))

except Exception as e:
    logging.exception(e)

except KeyboardInterrupt:
    pass

logging.info('Close the TSE.')
tse.close()
