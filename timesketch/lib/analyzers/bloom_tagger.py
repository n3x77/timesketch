"""Analyzer plugin for tagging."""
from timesketch.lib import emojis
from timesketch.lib.analyzers import interface
from timesketch.lib.analyzers import manager
from flor import BloomFilter
import re


class BloomTaggerSketchPlugin(interface.BaseSketchAnalyzer):
    """Sketch analyzer that uses bloom filters for tagging events."""

    NAME = 'bloom_tagger'
    DISPLAY_NAME = 'BloomTagger'
    DESCRIPTION = 'Tag events based on bloom filter matches'

    CONFIG_FILE = 'bloom.yaml'

    def __init__(self, index_name, sketch_id, timeline_id=None, config=None):
        """Initialize The Sketch Analyzer.

        Args:
            index_name: Elasticsearch index name
            sketch_id: Sketch ID
            timeline_id: The ID of the timeline.
            config: Optional dict that contains the configuration for the
                analyzer. If not provided, the default YAML file will be used.
        """
        self.index_name = index_name
        self._config = config
        super().__init__(index_name, sketch_id, timeline_id=timeline_id)

    def run(self):
        """Entry point for the analyzer.

        Returns:
            String with summary of the analyzer result.
        """
        config = self._config or interface.get_yaml_config(self.CONFIG_FILE)
        if not config:
            return 'Unable to parse the config file.'

        tag_results = []
        for name, tag_config in iter(config.items()):
            tag_result = self.tagger(name, tag_config)
            if tag_result:
                tag_results.append(tag_result)

        return ', '.join(tag_results)

    def tagger(self, name, config):
        """Tag and add emojis to events.

        Args:
            name: String with the name describing what will be tagged.
            config: A dict that contains the configuration See data/bloom.yaml
                for fields and documentation of what needs to be defined.

        Returns:
            String with summary of the analyzer result.
        """

        # We load the bloom_filter file that was defined in the bloom.yaml
        bloom_filter = config.get('bloom_filter')

        try:
            bf = BloomFilter()
            with open(bloom_filter, 'rb') as f:
                bf.read(f)
        except FileNotFoundError as e:
            return 'Error when loading bloom filter {}'.format(bloom_filter)
            
        create_view = config.get('create_view', False)
        view_name = config.get('view_name', name)
        tags = config.get('tags', [])
        emoji_names = config.get('emojis', [])
        emojis_to_add = [emojis.get_emoji(x) for x in emoji_names]

        hashes_md5 = None
        hashes_sha1 = None
        hashes_sha256 = None
        total_matches = 0
        matching_hash = set()
        events = self.event_stream(query_string="md5_hash:* OR sha1_hash:* OR sha256_hash:*", return_fields=['md5_hash, sha1_hash, sha256_hash'])

        # regexes for hash extraction out of the message
        re_hash_md5 = re.compile(r"\b[(A-F|a-f)0-9]{32}$")
        re_hash_sha1 = re.compile(r"\b[(A-F|a-f)0-9]{40}$")
        re_hash_sha256 = re.compile(r"\b[(A-F|a-f)0-9]{64}$")

        for event in events:
            # we build a unique set of all hashes that are in one event
            hashes = set()
            try:
                hashes_md5 = re.findall(re_hash_md5, event.source['md5_hash'])
                hashes_sha1 = re.findall(re_hash_sha1, event.source['sha1_hash'])
                hashes_sha256 = re.findall(re_hash_sha256, event.source['sha256_hash'])
            except KeyError as e:
                print(e)

            if hashes_md5 is not None:
                [hashes.add(h) for h in hashes_md5]
            if hashes_sha1 is not None: 
                [hashes.add(h) for h in hashes_sha1]
            if hashes_sha256 is not None:
                [hashes.add(h) for h in hashes_sha256]

            for h in hashes:
                print(h)
                # we check if the hash is in the bloomfilter
                if bf.check(bytes(h, encoding='ascii')) == True:
                    total_matches+=1
                    matching_hash.append(h)

                    event.add_tags(tags)
                    event.add_emojis(emojis_to_add)

            # Commit the event to the datastore.
            event.commit()

        # if create_view and total_matches:
        #     self.sketch.add_view(
        #         view_name, self.NAME, query_string=tags, query_dsl=query_dsl)

        return '{0:d} events tagged for [{1:s}]'.format(total_matches, name)


manager.AnalysisManager.register_analyzer(BloomTaggerSketchPlugin)
