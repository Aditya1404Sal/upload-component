# data-api

```wit
package betty-blocks:data-api;

interface data-api {
  record helper-context {
    application-id: string,
    action-id: string,
    log-id: string,
    encrypted-configurations: option<list<string>>,
    jwt: option<string>,
  }

  request: func(helper-context: helper-context, query: string, variables: string) -> result<string, string>;
}
```


# types 

```wit
package betty-blocks:types;

interface actions {
  type json-string = string;

  record payload {
    input: json-string,
    configurations: json-string,
  }

  record input {
    action-id: string,
    payload: payload,
  }

  record output {
    %result: json-string,
  }

  call: func(input: input) -> result<output, string>;

  health: func() -> result<string, string>;
}
```

# crud

```wit
package betty-blocks:crud;

interface crud {
  use betty-blocks:data-api/data-api.{helper-context};

  type json-string = string;

  record model {
    name: string
  }

  record object-field {
    name: string,
  }

  record property-key {
    name: string,
    kind: string,
    object-fields: option<list<object-field>>
  }

  record property-map {
      key: list<property-key>,
      value: option<json-string>
  }

  type property-mapping = list<property-map>;

  create: func(helper-context: helper-context, model: model, mapping: property-mapping, validation-sets: option<list<string>>) -> result<json-string, string>;
  update: func(helper-context: helper-context, model: model, record-id: string, mapping: property-mapping, validation-sets: option<list<string>>) -> result<json-string, string>;
  delete: func(helper-context: helper-context, model: model, record-id: string) -> result<json-string, string>;
}
```

# Data-api-utilities 
( Proposed )

```wit
interface data-api-utilities {

    record policy-field {
        key: string,
        value: string,
    }

    type policy-fields = list<policy-field>;

    record property {
        name: string,
    }

    record presigned-upload-url { //presigned-post
        url: string,
        fields: policy-fields,
        reference: string,
    }

    // mutation GenerateUpload(
    //     $model: String!,
    //     $property: String!,
    //     $contentType: String!,
    //     $fileName: String!
    //   ) {
    //     generateFileUploadRequest(
    //       modelName: $model
    //       propertyName: $property
    //       contentType: $contentType
    //       fileName: $fileName
    //     ) {
    //       ... on PresignedPostRequest {
    //         url
    //         fields
    //         reference
    //       }
    //     }
    //   }

    // fetch-presigned-post ?
    fetch-presigned-upload-url: func(model: string, property: property, content-type: string, filename: string) -> result<presigned-upload-url,string>;
}
```