use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;

/// Describes a custom field for template rendering.
#[derive(Debug, Clone, Serialize)]
pub struct CustomFieldDescriptor {
    pub name: String,
    pub label: String,
    pub field_type: FieldType,
    pub required: bool,
    pub help_text: Option<String>,
    pub min_length: Option<u64>,
    pub max_length: Option<u64>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub default_value: Option<Value>,
    pub enum_values: Option<Vec<Value>>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Text,
    Email,
    Url,
    Textarea,
    Number,
    Checkbox,
    Select,
}

/// Pre-compiled schema + validator + field descriptors.
pub struct CustomSchemaConfig {
    pub schema: Value,
    pub validator: jsonschema::Validator,
    pub fields: Vec<CustomFieldDescriptor>,
}

/// Validate that a schema is a flat object (no nested objects/arrays in properties).
///
/// The schema must have `"type": "object"` and a `"properties"` map where each
/// property's type is a scalar (`string`, `integer`, `number`, `boolean`).
/// Returns `Err` with a description if the schema is unsuitable.
pub fn validate_custom_schema(schema: &Value) -> Result<(), String> {
    let obj = schema
        .as_object()
        .ok_or_else(|| "schema must be a JSON object".to_string())?;

    match obj.get("type").and_then(Value::as_str) {
        Some("object") => {}
        Some(other) => return Err(format!("schema type must be \"object\", got \"{other}\"")),
        None => return Err("schema must have \"type\": \"object\"".to_string()),
    }

    let props = match obj.get("properties").and_then(Value::as_object) {
        Some(p) => p,
        None => return Ok(()), // no properties is valid (empty form)
    };

    for (name, prop) in props {
        let prop_obj = prop.as_object().ok_or_else(|| {
            format!("property \"{name}\" must be a JSON object")
        })?;
        if let Some(ty) = prop_obj.get("type").and_then(Value::as_str) {
            match ty {
                "string" | "integer" | "number" | "boolean" => {}
                "object" | "array" => {
                    return Err(format!(
                        "property \"{name}\" has type \"{ty}\"; nested objects/arrays are not supported"
                    ));
                }
                other => {
                    return Err(format!(
                        "property \"{name}\" has unsupported type \"{other}\""
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Extract field descriptors from a JSON Schema for template rendering.
///
/// Properties are iterated in insertion order (requires `preserve_order`
/// feature on `serde_json`).
pub fn extract_field_descriptors(schema: &Value) -> Vec<CustomFieldDescriptor> {
    let obj = match schema.as_object() {
        Some(o) => o,
        None => return Vec::new(),
    };

    let props = match obj.get("properties").and_then(Value::as_object) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let required_set: Vec<&str> = obj
        .get("required")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    props
        .iter()
        .map(|(name, prop)| {
            let prop_obj = prop.as_object();
            let ty = prop_obj
                .and_then(|o| o.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("string");
            let format = prop_obj
                .and_then(|o| o.get("format"))
                .and_then(Value::as_str);
            let has_enum = prop_obj
                .and_then(|o| o.get("enum"))
                .and_then(Value::as_array)
                .is_some();

            let field_type = match (ty, format, has_enum) {
                ("string", _, true) => FieldType::Select,
                ("string", Some("email"), _) => FieldType::Email,
                ("string", Some("uri"), _) => FieldType::Url,
                ("string", Some("textarea"), _) => FieldType::Textarea,
                ("integer" | "number", _, _) => FieldType::Number,
                ("boolean", _, _) => FieldType::Checkbox,
                _ => FieldType::Text,
            };

            let label = prop_obj
                .and_then(|o| o.get("title"))
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(|| title_case(name));

            CustomFieldDescriptor {
                name: name.clone(),
                label,
                field_type,
                required: required_set.contains(&name.as_str()),
                help_text: prop_obj
                    .and_then(|o| o.get("description"))
                    .and_then(Value::as_str)
                    .map(String::from),
                min_length: prop_obj
                    .and_then(|o| o.get("minLength"))
                    .and_then(Value::as_u64),
                max_length: prop_obj
                    .and_then(|o| o.get("maxLength"))
                    .and_then(Value::as_u64),
                minimum: prop_obj
                    .and_then(|o| o.get("minimum"))
                    .and_then(Value::as_f64),
                maximum: prop_obj
                    .and_then(|o| o.get("maximum"))
                    .and_then(Value::as_f64),
                default_value: prop_obj.and_then(|o| o.get("default")).cloned(),
                enum_values: prop_obj
                    .and_then(|o| o.get("enum"))
                    .and_then(Value::as_array)
                    .cloned(),
            }
        })
        .collect()
}

/// Extract custom_data fields from form body, coerce types per schema, return as Value.
///
/// HTML forms submit everything as strings. This function:
/// - Looks for keys starting with `custom_data[` and strips the prefix/suffix.
/// - Coerces values based on the schema property type.
/// - For booleans, iterates schema properties so that absent checkboxes map to `false`.
/// - Omits empty optional string fields from the result.
pub fn extract_and_coerce_custom_data(
    form_data: &HashMap<String, String>,
    schema: &Value,
) -> Value {
    let props = match schema
        .as_object()
        .and_then(|o| o.get("properties"))
        .and_then(Value::as_object)
    {
        Some(p) => p,
        None => return Value::Object(serde_json::Map::new()),
    };

    let required_set: Vec<&str> = schema
        .as_object()
        .and_then(|o| o.get("required"))
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    // Build a map of custom_data[key] -> value from the form submission
    let mut custom_values: HashMap<&str, &str> = HashMap::new();
    for (key, value) in form_data {
        if let Some(field_name) = key
            .strip_prefix("custom_data[")
            .and_then(|s| s.strip_suffix(']'))
        {
            custom_values.insert(field_name, value.as_str());
        }
    }

    let mut result = serde_json::Map::new();

    for (name, prop) in props {
        let ty = prop
            .as_object()
            .and_then(|o| o.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("string");

        match ty {
            "boolean" => {
                // Checkbox: present means true, absent means false
                let checked = custom_values
                    .get(name.as_str())
                    .is_some_and(|v| !v.is_empty());
                result.insert(name.clone(), Value::Bool(checked));
            }
            "integer" => {
                if let Some(raw) = custom_values.get(name.as_str()) {
                    if raw.is_empty() {
                        // Skip empty optional fields
                        if required_set.contains(&name.as_str()) {
                            result.insert(name.clone(), Value::Null);
                        }
                    } else if let Ok(n) = raw.parse::<i64>() {
                        result.insert(name.clone(), Value::Number(n.into()));
                    } else {
                        // Store as string; validation will catch the type mismatch
                        result.insert(name.clone(), Value::String((*raw).to_string()));
                    }
                }
            }
            "number" => {
                if let Some(raw) = custom_values.get(name.as_str()) {
                    if raw.is_empty() {
                        if required_set.contains(&name.as_str()) {
                            result.insert(name.clone(), Value::Null);
                        }
                    } else if let Ok(n) = raw.parse::<f64>() {
                        if let Some(num) = serde_json::Number::from_f64(n) {
                            result.insert(name.clone(), Value::Number(num));
                        } else {
                            result.insert(name.clone(), Value::String((*raw).to_string()));
                        }
                    } else {
                        result.insert(name.clone(), Value::String((*raw).to_string()));
                    }
                }
            }
            _ => {
                // string types
                if let Some(raw) = custom_values.get(name.as_str()) {
                    if raw.is_empty() && !required_set.contains(&name.as_str()) {
                        // Omit empty optional strings
                    } else {
                        result.insert(name.clone(), Value::String((*raw).to_string()));
                    }
                }
            }
        }
    }

    Value::Object(result)
}

/// Map jsonschema validation errors to field-level error messages.
///
/// Each error is mapped to `(field_name, message)`. For root-level errors
/// (e.g., missing required fields), the field name is extracted from the
/// instance path.
pub fn format_validation_errors(
    errors: &[jsonschema::error::ValidationError<'_>],
) -> Vec<(String, String)> {
    errors
        .iter()
        .map(|err| {
            let path = err.instance_path().as_str();
            // instance_path is a JSON pointer like "/field_name"
            let field = path.strip_prefix('/').unwrap_or(path);
            (field.to_string(), err.to_string())
        })
        .collect()
}

/// Convert "snake_case" or "kebab-case" field names to title case labels.
fn title_case(s: &str) -> String {
    s.split(|c: char| c == '_' || c == '-')
        .filter(|w| !w.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => {
                    let upper: String = first.to_uppercase().collect();
                    let rest: String = chars.collect();
                    format!("{upper}{rest}")
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validate_custom_schema_rejects_nested_objects() {
        let schema = json!({
            "type": "object",
            "properties": {
                "address": {
                    "type": "object",
                    "properties": {
                        "street": { "type": "string" }
                    }
                }
            }
        });
        let result = validate_custom_schema(&schema);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nested objects/arrays"));
    }

    #[test]
    fn validate_custom_schema_rejects_arrays() {
        let schema = json!({
            "type": "object",
            "properties": {
                "tags": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            }
        });
        let result = validate_custom_schema(&schema);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nested objects/arrays"));
    }

    #[test]
    fn validate_custom_schema_accepts_flat_object() {
        let schema = json!({
            "type": "object",
            "properties": {
                "company": { "type": "string" },
                "age": { "type": "integer" },
                "score": { "type": "number" },
                "active": { "type": "boolean" }
            }
        });
        assert!(validate_custom_schema(&schema).is_ok());
    }

    #[test]
    fn validate_custom_schema_rejects_non_object_type() {
        let schema = json!({
            "type": "string"
        });
        let result = validate_custom_schema(&schema);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be \"object\""));
    }

    #[test]
    fn validate_custom_schema_accepts_empty_properties() {
        let schema = json!({
            "type": "object",
            "properties": {}
        });
        assert!(validate_custom_schema(&schema).is_ok());
    }

    #[test]
    fn validate_custom_schema_accepts_no_properties() {
        let schema = json!({
            "type": "object"
        });
        assert!(validate_custom_schema(&schema).is_ok());
    }

    #[test]
    fn extract_field_descriptors_produces_correct_types() {
        let schema = json!({
            "type": "object",
            "required": ["email", "company"],
            "properties": {
                "company": {
                    "type": "string",
                    "title": "Company Name",
                    "description": "Your company"
                },
                "contact_email": {
                    "type": "string",
                    "format": "email"
                },
                "website": {
                    "type": "string",
                    "format": "uri"
                },
                "bio": {
                    "type": "string",
                    "format": "textarea",
                    "maxLength": 500
                },
                "age": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 150
                },
                "score": {
                    "type": "number"
                },
                "newsletter": {
                    "type": "boolean"
                },
                "plan": {
                    "type": "string",
                    "enum": ["free", "pro", "enterprise"]
                }
            }
        });

        let fields = extract_field_descriptors(&schema);
        assert_eq!(fields.len(), 8);

        let company = &fields[0];
        assert_eq!(company.name, "company");
        assert_eq!(company.label, "Company Name");
        assert_eq!(company.field_type, FieldType::Text);
        assert!(company.required);
        assert_eq!(company.help_text.as_deref(), Some("Your company"));

        let contact = &fields[1];
        assert_eq!(contact.name, "contact_email");
        assert_eq!(contact.field_type, FieldType::Email);
        assert!(!contact.required);
        // Auto-generated label from field name
        assert_eq!(contact.label, "Contact Email");

        let website = &fields[2];
        assert_eq!(website.field_type, FieldType::Url);

        let bio = &fields[3];
        assert_eq!(bio.field_type, FieldType::Textarea);
        assert_eq!(bio.max_length, Some(500));

        let age = &fields[4];
        assert_eq!(age.field_type, FieldType::Number);
        assert_eq!(age.minimum, Some(0.0));
        assert_eq!(age.maximum, Some(150.0));

        let score = &fields[5];
        assert_eq!(score.field_type, FieldType::Number);

        let newsletter = &fields[6];
        assert_eq!(newsletter.field_type, FieldType::Checkbox);

        let plan = &fields[7];
        assert_eq!(plan.field_type, FieldType::Select);
        assert!(plan.enum_values.is_some());
        assert_eq!(plan.enum_values.as_ref().map(|v| v.len()), Some(3));
    }

    #[test]
    fn extract_and_coerce_string_fields() {
        let schema = json!({
            "type": "object",
            "properties": {
                "company": { "type": "string" }
            }
        });

        let mut form = HashMap::new();
        form.insert("custom_data[company]".to_string(), "Acme Corp".to_string());

        let result = extract_and_coerce_custom_data(&form, &schema);
        assert_eq!(result["company"], "Acme Corp");
    }

    #[test]
    fn extract_and_coerce_integer_fields() {
        let schema = json!({
            "type": "object",
            "properties": {
                "age": { "type": "integer" }
            }
        });

        let mut form = HashMap::new();
        form.insert("custom_data[age]".to_string(), "25".to_string());

        let result = extract_and_coerce_custom_data(&form, &schema);
        assert_eq!(result["age"], 25);
        assert!(result["age"].is_i64());
    }

    #[test]
    fn extract_and_coerce_number_fields() {
        let schema = json!({
            "type": "object",
            "properties": {
                "score": { "type": "number" }
            }
        });

        let mut form = HashMap::new();
        form.insert("custom_data[score]".to_string(), "3.14".to_string());

        let result = extract_and_coerce_custom_data(&form, &schema);
        assert_eq!(result["score"], 3.14);
    }

    #[test]
    fn extract_and_coerce_checkbox_present() {
        let schema = json!({
            "type": "object",
            "properties": {
                "newsletter": { "type": "boolean" }
            }
        });

        let mut form = HashMap::new();
        form.insert(
            "custom_data[newsletter]".to_string(),
            "true".to_string(),
        );

        let result = extract_and_coerce_custom_data(&form, &schema);
        assert_eq!(result["newsletter"], true);
    }

    #[test]
    fn extract_and_coerce_checkbox_absent_is_false() {
        let schema = json!({
            "type": "object",
            "properties": {
                "newsletter": { "type": "boolean" }
            }
        });

        // No custom_data[newsletter] in form — checkbox was unchecked
        let form: HashMap<String, String> = HashMap::new();

        let result = extract_and_coerce_custom_data(&form, &schema);
        assert_eq!(result["newsletter"], false);
    }

    #[test]
    fn extract_omits_empty_optional_strings() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" },
                "bio": { "type": "string" }
            }
        });

        let mut form = HashMap::new();
        form.insert("custom_data[name]".to_string(), "Alice".to_string());
        form.insert("custom_data[bio]".to_string(), String::new());

        let result = extract_and_coerce_custom_data(&form, &schema);
        assert_eq!(result["name"], "Alice");
        // bio is empty and optional, so it should be omitted
        assert!(result.get("bio").is_none());
    }

    #[test]
    fn extract_includes_empty_required_strings() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        });

        let mut form = HashMap::new();
        form.insert("custom_data[name]".to_string(), String::new());

        let result = extract_and_coerce_custom_data(&form, &schema);
        // Required field submitted as empty should still be included
        // so that validation catches it
        assert_eq!(result["name"], "");
    }

    #[test]
    fn format_validation_errors_maps_to_fields() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string", "minLength": 1 },
                "age": { "type": "integer", "minimum": 0 }
            }
        });

        let validator = jsonschema::validator_for(&schema)
            .expect("valid schema");
        let instance = json!({ "age": -1 });

        let errors: Vec<_> = validator.iter_errors(&instance).collect();
        assert!(!errors.is_empty());

        let formatted = format_validation_errors(&errors);
        assert!(!formatted.is_empty());
        // Each error should have a field name and message
        for (field, msg) in &formatted {
            assert!(!msg.is_empty(), "error message should not be empty");
            // field may be empty for root-level errors (like missing required)
            let _ = field;
        }
    }

    #[test]
    fn title_case_conversion() {
        assert_eq!(title_case("company_name"), "Company Name");
        assert_eq!(title_case("contact-email"), "Contact Email");
        assert_eq!(title_case("simple"), "Simple");
        assert_eq!(title_case("already_Good"), "Already Good");
    }

    #[test]
    fn extract_ignores_non_custom_data_keys() {
        let schema = json!({
            "type": "object",
            "properties": {
                "company": { "type": "string" }
            }
        });

        let mut form = HashMap::new();
        form.insert("email".to_string(), "test@example.com".to_string());
        form.insert("password".to_string(), "secret".to_string());
        form.insert("custom_data[company]".to_string(), "Acme".to_string());

        let result = extract_and_coerce_custom_data(&form, &schema);
        let obj = result.as_object().expect("should be object");
        assert_eq!(obj.len(), 1);
        assert_eq!(result["company"], "Acme");
    }
}
