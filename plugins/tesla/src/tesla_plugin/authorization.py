"""Identity of the authorization actually used for one provider request."""
from dataclasses import dataclass, field
import json


@dataclass(frozen=True)
class Authorization:
    generation: int
    region: str
    scopes: str
    # Compare the original persisted bytes; never encrypt again to compare.
    tokens: bytes = field(repr=False)
    access_token: str = field(repr=False)

    @classmethod
    def from_row(cls, store, row):
        return cls(row["generation"], row["region"], row["scopes"], row["tokens"],
                   store.unseal(row["tokens"])["access_token"])

    @property
    def grants(self):
        return set(json.loads(self.scopes))

    def matches(self, row):
        return bool(row and row["status"] == "active" and row["generation"] == self.generation
                    and row["tokens"] == self.tokens and row["scopes"] == self.scopes
                    and row["region"] == self.region)
