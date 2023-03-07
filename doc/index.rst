Welcome to Enbox documentation
##############################

.. Caption of toctrees are not translated into latex, hence the dirty trick
.. below. See https://github.com/sphinx-doc/sphinx/issues/3169 for more infos.
.. Basically, we ask the latex backend to generate a \part{} section for each
.. toctree caption using the `raw' restructuredtext directive.

.. raw:: latex

   \part{User Guide}

.. toctree::
   :numbered:
   :caption: User manual

   main


.. raw:: latex

   \part{Integration Guide}

.. toctree::
   :numbered:
   :caption: Integration manual

   install


.. raw:: latex

   \part{API guide}

.. toctree::
   :maxdepth: 2
   :numbered:
   :caption: API

   api


.. raw:: latex

   \part{Appendix}

.. We use the latex_appendices setting into conf.py to benefit from native latex
.. appendices section numbering scheme. As a consequence, there is no need to
.. generate appendix entries for latex since already requested through the
.. latex_appendices setting. Hence, the `only' restructuredtext directive
.. below...

.. only:: html

   .. toctree::
      :caption: Appendix

      glossary
      genindex
      todo
