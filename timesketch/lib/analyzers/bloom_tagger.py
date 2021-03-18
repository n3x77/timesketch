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

        # load values from configuration file defined in the bloom.yaml
        bloom_filter = config.get('bloom_filter')
        try:
            bf = BloomFilter()
            with open(bloom_filter, 'rb') as f:
                bf.read(f)
        except FileNotFoundError as e:
            return 'Error: {} when loading bloom filter {}'.format(e, bloom_filter)

        query = config.get('query_string')
        fields = config.get('fields', [])
        tags = config.get('tags', [])
        emoji_names = config.get('emojis', [])
        emojis_to_add = [emojis.get_emoji(x) for x in emoji_names]
        create_view = config.get('create_view', False)
        view_name = config.get('view_name', name)

        total_matches = 0
        matches = set()

        event_counter = 0
        list_counter = 0
        str_counter = 0
        events = self.event_stream(query_string=query, return_fields=fields)

        # regexes for hash extraction out of the message
        re_hash_md5 = re.compile(r"\b[(A-F|a-f)0-9]{32}$")
        re_hash_sha1 = re.compile(r"\b[(A-F|a-f)0-9]{40}$")
        re_hash_sha256 = re.compile(r"\b[(A-F|a-f)0-9]{64}$")

        for event in events:
            event_counter += 1
            for field in fields:
                f = event.source.get(field)

                if f is None:
                    continue

                if isinstance(f, list):
                    list_counter += 1
                    continue
                if isinstance(f, str):
                    str_counter += 1
                # make sure that the filters are build lowercase
                # TODO: We need to check if this makes sense for every type: ip, domain, url
                    if str.encode(f.lower()) in bf:
                        total_matches += 1
                        matches.add(f)
                        event.add_tags(tags)
                        event.add_emojis(emojis_to_add)
            event.commit()

        if create_view and event_counter:
            # Prepare the tags so that they can be used in the query
            for i, t in enumerate(tags):
                tags[i] = '"{}"'.format(t)
            # prepare LUCENE
            q = ' AND '.join(tags)
            self.sketch.add_view(
                view_name, self.NAME, query_string='tag CONTAINS ({})'.format(q))

        return '{0:d} events tagged for [{1:s}] of {2:d} events and {3:d} lists and {4:d} strings and {5:d} matches'.format(total_matches, name,  event_counter, list_counter, str_counter, total_matches)


manager.AnalysisManager.register_analyzer(BloomTaggerSketchPlugin)
