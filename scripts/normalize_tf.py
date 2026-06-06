def normalize_hcl2(raw):
    """
    Convert python-hcl2 output (lists of dicts)
    into flat dict format that OPA Rego can query easily.
    Handles both old hcl2 (scalar values) and new hcl2 (list-wrapped values).
    """
    normalized = {}

    for top_key, top_value in raw.items():
        if not isinstance(top_value, list):
            normalized[top_key] = top_value
            continue

        normalized[top_key] = {}

        for item in top_value:
            if not isinstance(item, dict):
                continue
            for resource_type, resource_value in item.items():
                clean_type = resource_type.strip('"').strip("'")

                if clean_type not in normalized[top_key]:
                    normalized[top_key][clean_type] = {}

                if isinstance(resource_value, list):
                    for rv in resource_value:
                        if isinstance(rv, dict):
                            for rname, rconfig in rv.items():
                                clean_name = rname.strip('"').strip("'")
                                if isinstance(rconfig, list) and len(rconfig) == 1:
                                    rconfig = rconfig[0]
                                normalized[top_key][clean_type][clean_name] = deep_unwrap(rconfig)
                elif isinstance(resource_value, dict):
                    for rname, rconfig in resource_value.items():
                        clean_name = rname.strip('"').strip("'")
                        if isinstance(rconfig, list) and len(rconfig) == 1:
                            rconfig = rconfig[0]
                        normalized[top_key][clean_type][clean_name] = deep_unwrap(rconfig)

    return normalized


def deep_unwrap(obj):
    """
    Recursively unwrap single-element lists (new hcl2 behavior)
    and strip surrounding HCL quotes from string values.
    """
    if isinstance(obj, dict):
        return {k: deep_unwrap(v) for k, v in obj.items()
                if not k.startswith('__')}
    elif isinstance(obj, list):
        if len(obj) == 1:
            return deep_unwrap(obj[0])
        return [deep_unwrap(i) for i in obj]
    elif isinstance(obj, str):
        s = obj.strip()
        if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
            return s[1:-1]
        return s
    else:
        return obj
