# -*- coding: utf-8 -*-
#
# Enbox documentation build configuration file, created by sphinx-quickstart
#
# This file is execfile()d with the current directory set to its
# containing dir.
#
# Note that not all possible configuration values are present in this
# autogenerated file.
#
# All configuration values have a default; values that are commented out
# serve to show the default.

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys

# -- General configuration ------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
#
# needs_sphinx = '1.0'

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = ['sphinx.ext.intersphinx',
              'sphinx.ext.todo',
              'sphinx.ext.mathjax',
              'sphinx.ext.ifconfig',
              'sphinx.ext.graphviz',
              'sphinxcontrib.plantuml',
              'sphinx_rtd_theme',
              'sphinx.ext.autosectionlabel',
              'breathe']

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
#
# source_suffix = ['.rst', '.md']
source_suffix = '.rst'

# The master toctree document.
root_doc = 'html'
master_title = u'Enbox Documentation'

# General information about the project.
project = u'Enbox'
copyright = u"2022, Interface Concept"
author = u"Grégor Boirie"

# The version info for the project you're documenting, acts as replacement for
# |version| and |release|, also used in various other places throughout the
# built documents.
#
# The short X.Y version.
#version = u'1.0'
version = os.getenv('VERSION', u'??')

# The full version, including alpha/beta/rc tags.
#release = u'1.0'
release = version

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#
# This is also used if you do content translation via gettext catalogs.
# Usually you set "language" from the command line for these cases.
language = "en"

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This patterns also effect to html_static_path and html_extra_path
exclude_patterns = []

# The name of the Pygments (syntax highlighting) style to use.
#pygments_style = 'sphinx'

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = True

# -- Setup base URL for manpage role -------------------------------------------
# see https://www.sphinx-doc.org/en/master/usage/restructuredtext/roles.html#role-manpage
manpages_url = "https://man7.org/linux/man-pages/man{section}/{page}.{section}.html"

# -- Options for breathe output -------------------------------------------
doxyxmldir = os.getenv('DOXYXMLDIR')
if doxyxmldir and not os.path.isdir(doxyxmldir):
    print('{}: Invalid Doxygen XML directory'.format(os.path.basename(sys.argv[0])),
          file=sys.stderr)
    sys.exit(1)

breathe_default_project        = project
breathe_projects               = { breathe_default_project: doxyxmldir }
breathe_domain_by_extension    = { "h" : "c", "c": "c" }
breathe_show_include           = False
breathe_order_parameters_first = True
breathe_separate_member_pages  = False
breathe_default_members        = ('members', 'undoc-members')

# -- Options for HTML output ----------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = 'sphinx_rtd_theme'

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
html_theme_options = {
        'collapse_navigation': False,
        'sticky_navigation': True,
}

# Custom sidebar templates, must be a dictionary that maps document names
# to template names.
#
# This is required for the alabaster theme
# refs: http://alabaster.readthedocs.io/en/latest/installation.html#sidebars
html_sidebars = {
    '**': [
        'relations.html',  # needs 'show_related': True theme option to display
        'searchbox.html',
    ]
}

# Show Copyright in HTML footer
html_show_copyright = True

# Do not show "Created using Sphinx" in HTML footer.
html_show_sphinx = False

# -- Options for LaTeX output ---------------------------------------------

latex_elements = {
    # The paper size ('letterpaper' or 'a4paper').
    'papersize': 'a4paper',
    # Font size
    'pointsize': '12pt',
}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
    ('latex', 'enbox.tex', master_title, author, 'manual')
]

# Request latex backend to generate the following appendix entries to benefit
# from its appendix section numbering scheme. This requires some special
# handling / dirty hack into index.rst to prevent from duplicating toctree
# entries into generated document.
# See comments into latex.rst for more informations.
latex_toplevel_sectioning = 'chapter'
latex_appendices = [ 'glossary', 'todo' ]
latex_show_urls = 'footnote'
latex_show_pagerefs = True

# -- Options for manual page output ---------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
#man_pages = [
#    (root_doc, 'enbox', master_title, author, 1)
#]

# -- Options for Texinfo output -------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author, dir menu entry, description,
# category)
texinfo_documents = [
    ('info',
     'enbox',
     master_title,
     author,
     'enbox',
     'Enbox sandboxing system',
     'System-administration'),
]

# Request texinfo backend to generate the following appendix entries to benefit
# from its appendix section numbering scheme.
texinfo_appendices = [ 'glossary', 'todo' ]
texinfo_domain_indices = True
texinfo_show_urls = 'footnote'
texinfo_no_detailmenu = True
texinfo_cross_references = True

# -- Options for InterSphinx output -------------------------------------------

# Example configuration for intersphinx: refer to the Python standard library.
intersphinx_mapping = {'https://docs.python.org/': None}
