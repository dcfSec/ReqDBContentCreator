from reqdb import ReqDB


class Rollback:
    catalogues = []
    topics = []
    requirements = []
    tags = []
    extraEntries = []
    extraTypes = []

    @classmethod
    def rollBackItems(
        cls,
        items: list,
        target: type[
            ReqDB.Requirements
            | ReqDB.ExtraTypes
            | ReqDB.Topics
            | ReqDB.Tags
            | ReqDB.Catalogues
        ],
    ):
        for item in items:
            target.delete(item, force=True)
        items = []

    @classmethod
    def rollbackAll(cls, client: ReqDB):
        cls.rollBackItems(cls.requirements, client.Requirements)
        cls.rollBackItems(cls.extraTypes, client.ExtraTypes)
        cls.rollBackItems(cls.topics, client.Topics)
        cls.rollBackItems(cls.tags, client.Tags)
        cls.rollBackItems(cls.catalogues, client.Catalogues)
