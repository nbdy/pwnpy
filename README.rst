pwnpy
=====

|Build Status|

wardriving tool

features:
---------

-  runs on any computer
-  fully automatic
-  `modular`_
-  `LiPo SHIM`_

   -  you might want to use `this`_

-  `2.9 inch ePaper display`_

show and tell
-------------

|asciicast|

.. _how-to:

how to...
---------

...use it
~~~~~~~~~

.. code:: shell

   ./pwn.py -c config.json

...install dependencies
~~~~~~~~~~~~~~~~~~~~~~~

::

   pip3 install --upgrade -r requirements.txt

the bluetooth module depends on `pybt`_\  most likely there will be
issues with installing gattlib follow the instructions in the pybt repo

...install it
~~~~~~~~~~~~~

.. code:: shell

   usage: ./install.py {arguments}
   {arguments}:
       -ia --install-autostart
       -ua --uninstall-autostart
       -d  --dependencies
       -db --database
       --help

.. _modular: https://github.com/smthnspcl/pwnpy/tree/master/modules
.. _LiPo SHIM: https://shop.pimoroni.com/products/lipo-shim
.. _this: https://github.com/smthnspcl/clean-shutdown
.. _2.9 inch ePaper display: https://www.waveshare.com/wiki/2.9inch_e-Paper_Module
.. _pybt: https://github.com/smthnspcl/pybt

.. |Build Status| image:: https://build.eberlein.io/buildStatus/icon?job=python_pwnpy
   :target: https://build.eberlein.io/job/python_pwnpy/
.. |asciicast| image:: https://asciinema.org/a/299821.svg
   :target: https://asciinema.org/a/299821