Usage
=====
The tse.py package has an easy to use API. This page describes 
the most common use cases. First, some basic explanations.

In most API for TSE, a distinction is made between Cients and Users. 
However, this separation is not really strict and often causes 
misunderstandings, because a client can login as a user with
a specific role and perform actions. In our API there are only 
users and no clients. Every point of sale that uses the TSE is
a user that can have specific roles.

Roles are used to restrict the calling of certain methods. There 
are two possible roles TSERole.ADMIN and TSERole.TIME_ADMIN. The 
role needed to call a method is described in the documentation 
of the method.

If the TSE is used exclusively by only one user, then this can
also remain open. Opening and closing before and after writing 
is only necessary if several users share one TSE. If the TSE is
currently being used by another user, then a TSEInUseError is
raised.

Installation
------------
Normally, the installation is done by using the Python package 
mamager PIP .

.. code:: bash

        $ pip install tse.py

Get informations
----------------
To get information about the used TSE and its state the info() 
method can be called. This returns an instance of the TSEInfo class.
See: :class:`tse.TSEInfo`

.. code:: python

    from tse.epson import TSE

    tse = TSE(<tse_id>, <host_ip>)
    tse.open()

    try:
        print(tse.info())
    except Exception as ex:
        print(ex)

    tse.close()

Initialization
--------------
Before the TSE can be used, it must be initialized. During 
initialization the PUK, the PIN for the TSERole.ADMIN and
the PIN for the TSERole.TIME_ADMIN are set.

If an Epson TSE is used, then the TSE ID and the IP address of 
the TSE host (server or printer) are required. The TSE ID can 
be found in the web interface of the server.

To create users, a user with the TSERole.ADMIN role must be logged 
in. The only user who can assume this role is the Adminstrator user. 
This user is an internal user that does not need to be created.

.. mermaid::

    flowchart TD
        A[run self-test] --> B[initialize]
        B --> C[login TSERole.ADMIN]
        C --> D[register secret]
        D --> E[register client]
        E --> F[logout TSERole.ADMIN]

.. code:: python

    from tse.epson import TSE

    tse = TSE(<tse_id>, <host_ip>)
    tse.open()

    try:
        tse.run_self_test()
        tse.initialize('123456', '12345', '54321')
        tse.login_user('Administrator', TSERole.ADMIN, '12345')
        tse.register_secret('new_secret')
        tse.register_user('pos1')
        tse.logout_user('Adminstrator', TSERole.ADMIN)
    except Exception as ex:
        print(ex)

    tse.close()


Daily operation
---------------
To log transactions, the time of the TSE must be set first. For this 
purpose the client must log in with the role TSERole.TIME_ADMIN. 
To create transactions the user must also be logged in as 
TSERole.TIME_ADMIN.

The TSE needs to perform a self-test on a regular basis in order to 
ensure the proper working of the signature functionality.
After 25 hours the status *needs_self_test* in the TSEInfo will be
false and most functions will raise the *TSENeedsSelfTestError* exception.
Now, you have to perform a self-test. After performing the self-test, you 
need to update the time again.

.. mermaid::

    flowchart TD
        A[run self-test] --> B[login as TSERole.TIME_ADMIN]
        B --> C[update TSE time]
        C --> D[do transactions]
        D --> E[run self-test]
        E --> F[update TSE time]
        F --> G[logout TSERole.TIME_ADMIN]

.. code:: python

    from tse.epson import TSE
    from datetime import datetime

    tse = TSE(<tse_id>, <host_ip>)
    tse.open()
    try:
        date_time = datetime(2022, 7, 11, 23, 59, 59)
        tse.run_self_test()
        tse.login_user('pos1', TSERole.TIME_ADMIN, '54321')
        tse.update_time('pos1', date_time)
        transaction = tse.start_transaction('pos1', 'data', 'type')
        tse.update_transaction('pos1', transaction, 'data', 'type')
        tse.finish_transaction('pos1', transaction, 'data', 'type')
        tse.run_self_test()
        tse.update_time('pos1', date_time)
        tse.logout_user('pos1', TSERole.TIME_ADMIN)
    except Exception as ex:
        print(ex)

    tse.close()

Export
------
The data stored in the TSE can be exported for archiving or for 
transfer to the fiscal authorities.
Only the Adminstrator user can export the data.

.. code:: python

    from tse.epson import TSE
    from datetime import datetime

    tse = TSE(<tse_id>, <host_ip>)
    tse.open()
    try:
        tse.login_user('Administrator', TSERole.ADMIN, '12345')
        tse.export(Path('/home/lluar/tse.tar'), 'pos1')
        tse.logout_user('Adminstrator', TSERole.ADMIN)
    except Exception as ex:
        print(ex)

    tse.close()
