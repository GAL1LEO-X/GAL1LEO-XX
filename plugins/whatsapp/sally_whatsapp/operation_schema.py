"""Schema repairs shared by catalog generation and wire normalization."""
from jsonschema import Draft202012Validator


def complete_schema(schema):
    """Describe the bridge's existing container and path requirements exactly."""
    def pagination(node):
        for name, child in node.get('properties', {}).items():
            if name in ('limit', 'offset') and child.get('type') in ('number', 'integer'):
                child['type'] = 'integer'
            pagination(child)
    pagination(schema)
    for child in schema['properties']['path'].get('properties', {}).values():
        child['type'] = 'string'
    required = [name for name, child in schema['properties'].items()
                if not Draft202012Validator(child).is_valid({})]
    if required:
        schema['required'] = required
    return schema


def normalize_paging(schema, value):
    """JSON Schema accepts 1.0 as integer; emit 1, never provider query '1.0'.

    Called only after full validation, on the private arguments copy. No string,
    fractional value or boolean is coerced to repair invalid user input.
    """
    if not isinstance(value, dict):
        return
    for name, child in schema.get('properties', {}).items():
        if name not in value:
            continue
        if name in ('limit', 'offset', 'messages') and child.get('type') == 'integer':
            value[name] = int(value[name])
        else:
            normalize_paging(child, value[name])
