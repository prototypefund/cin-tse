from tse.epson import TSE
import logging
logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.DEBUG)

tse = TSE(
        'TSE_FDDA56DAA09F7FAC125E58F45945D1E4AC9ED9133F75C310953B632B42BBBA56',
        '10.0.0.2')

logging.info('Open the TSE.')
tse.open()

logging.info('Make factory reset.\n')
logging.info('THE TSE NEEDS A RESTART!\n')
tse.factory_reset()

logging.info('Close the TSE.')
tse.close()
