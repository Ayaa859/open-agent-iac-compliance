def normalize_hcl2(raw):
    """
    Convert python-hcl2 output (lists of dicts) 
    into flat dict format that OPA Rego can query easily
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
                # Clean up escaped quotes in resource type names
                clean_type = resource_type.strip('"').strip("'")
                
                if clean_type not in normalized[top_key]:
                    normalized[top_key][clean_type] = {}
                
                if isinstance(resource_value, list):
                    for rv in resource_value:
                        if isinstance(rv, dict):
                            for rname, rconfig in rv.items():
                                clean_name = rname.strip('"').strip("'")
                                # Flatten config if it's a list of one dict
                                if isinstance(rconfig, list) and len(rconfig) == 1:
                                    rconfig = rconfig[0]
                                normalized[top_key][clean_type][clean_name] = rconfig
                elif isinstance(resource_value, dict):
                    for rname, rconfig in resource_value.items():
                        clean_name = rname.strip('"').strip("'")
                        if isinstance(rconfig, list) and len(rconfig) == 1:
                            rconfig = rconfig[0]
                        normalized[top_key][clean_type][clean_name] = rconfig
    
    return normalized