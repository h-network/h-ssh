"""An entry point that cannot be imported: the library it needs is missing.
The registry reports it by name and loads everything else."""

raise ImportError("hssh_broken needs a library that is not installed")
