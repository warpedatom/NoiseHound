"""NoiseHound - detection-aware Active Directory attack-path scoring.

Re-ranks BloodHound attack paths by expected detection cost instead of hop
count, so an operator can ask "what is the quietest way to Domain Admin"
rather than just "what is a way".
"""

__version__ = "1.0.0"
__author__ = "Velkris | DreadHost Research"

# Default score applied to edge types absent from the corpus. Deliberately
# mid-high so that gaps in the corpus fail safe (over-report risk) rather than
# silently routing an operator through an unscored, potentially loud edge.
DEFAULT_UNKNOWN_NOISE = 60
