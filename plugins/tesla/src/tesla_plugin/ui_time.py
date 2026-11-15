"""Local presentation timers. These never evaluate command admission."""
from html import escape
import math


def age_label(age, maximum, quality_label=''):
    if type(age) not in (int, float) or not math.isfinite(age):
        return '<span>Unknown age</span>'
    if age < -0.001:
        return '<span>Future timestamp</span>'
    age = max(0, age)
    ago = f'{int(age)} s ago' if age < 60 else f'{int(age)//60} min ago' if age < 3600 else f'{int(age)//3600} h ago'
    label = quality_label or ('Recent' if age <= maximum else 'Historical')
    return ('<span data-sample-age="'+str(age)+'" data-age-limit="'+str(maximum)+'" data-quality-label="'
            +escape(quality_label, quote=True)+'"><span class="observation-label">'+escape(label+' · '+ago)+'</span></span>')


def expiry_attributes(seconds):
    """Expire a rendered assessment conservatively; do not infer a new state."""
    if seconds is None:
        return ''
    return ' data-evidence-expires-in="'+str(max(0, seconds))+'"'
