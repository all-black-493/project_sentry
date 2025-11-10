# for shared Pydantic schemas in app/models/ . For instance, if multiple attack modules need a common TargetEndpoint schema, define it once
# import and reuse this in any router that needs to know where to send payloads

from pydantic import BaseModel, HttpUrl

class TargetEndpoint(BaseModel):
    url: HttpUrl
    api_key: str

