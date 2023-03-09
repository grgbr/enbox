.. Caption of toctrees are not translated into texinfo, hence the dirty trick
.. below.
.. Basically, we ask the texinfo backend to generate an additional top-level
.. section for each manual and include the corresponding manual file...

Welcome to Enbox documentation
##############################

User Guide
^^^^^^^^^^

.. include:: main.rst

Integration Guide
^^^^^^^^^^^^^^^^^

.. include:: install.rst

API Guide
^^^^^^^^^

.. include:: api.rst

.. We use the texinfo_appendices setting into conf.py to benefit from native
.. texinfo appendices section handling. As a consequence, there is no need to
.. generate appendix entries for texinfo since already requested through the
.. texinfo_appendices setting.
