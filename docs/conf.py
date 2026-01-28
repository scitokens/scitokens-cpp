# Configuration file for the Sphinx documentation builder.
# 
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'SciTokens C++'
copyright = '2024, SciTokens Team'
author = 'SciTokens Team'
release = '1.0.2'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'breathe',
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon'
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output ------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# -- Breathe Configuration --------------------------------------------------

breathe_projects = {
    "scitokens-cpp": "_build/doxygen/xml"
}
breathe_default_project = "scitokens-cpp"

# -- Doxygen integration ----------------------------------------------------

import subprocess
import os

def run_doxygen(app, config):
    """Run doxygen to generate XML for breathe"""
    try:
        subprocess.run(['doxygen', 'Doxyfile'], cwd='..', check=True)
    except subprocess.CalledProcessError:
        print("Failed to run doxygen")

def setup(app):
    app.connect('config-inited', run_doxygen)