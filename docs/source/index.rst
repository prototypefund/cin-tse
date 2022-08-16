.. tse.py documentation master file, created by
   sphinx-quickstart on Mon May  2 17:44:36 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

The tse.py package
==================

.. toctree::
   :hidden:
   :maxdepth: 2
   :caption: Contents:

   usage
   specs
   API <api/tse>

A Python package to access security modules (TSE) of the German 
Fiscal Authority.

The German Friscal Authority has determined that the transactions 
of all cash register systems used on the German market must be recorded
unchangeably. Certified external storage media are used for this purpose. 
The storage is accessed via certified libraries or APIs.

To interact with the TSEs, the package implements a vendor-independent API. 
Currently, TSEs from Epson are supported. Support for other manufacturers 
is planned for the future.

.. toctree::
   :caption: Links
   :maxdepth: 1

   Gitlab Project <https://gitlab.com/ccodein/tse.py/>

Sponsored by:
-------------

.. image:: _static/BMBF_RGB_Gef_L_e-1.jpg
   :height: 100
   :target: https://www.bmbf.de/

.. image:: _static/PrototypeFund-P-Logo.png
   :height: 100
   :target: https://prototypefund.de/
