"""Tests for TaggerSketchPlugin."""
import yaml

from timesketch.lib import emojis
from timesketch.lib.testlib import BaseTest


class TestBloomTaggerPlugin(BaseTest):
    """Tests the functionality of the analyzer."""

    def _config_validation(self, config):
        """Validate that all items of a config are valid."""
        filter = config.get('bloom_filter')
        self.assertIsNotNone(filter)
        self.assertIsInstance(filter, str)

        query = config.get('query_string')
        self.assertIsNotNone(query)
        self.assertIsInstance(query, str)

        fields = config.get('fields')
        self.assertIsNotNone(fields)
        self.assertIsInstance(fields, (list, tuple))

        emojis_to_add = config.get('emojis')
        if emojis_to_add:
            self.assertIsInstance(emojis_to_add, (list, tuple))
            for emoji_name in emojis_to_add:
                emoji_code = emojis.get_emoji(emoji_name)
                self.assertNotEqual(emoji_code, '')

        tags = config.get('tags')
        if tags:
            self.assertIsInstance(tags, (list, tuple))

        create_view = config.get('create_view')
        if create_view:
            self.assertIsInstance(create_view, bool)

    # TODO: Add tests for the tagger.
    def test_config(self):
        """Tests that the config is valid."""
        test_config = yaml.safe_load("""
        place_holder:
          bloom_filter: '*'
          query_string: '*'
          fields: ['place-holder']
          tags: ['place-holder']
          emojis: ['ID_BUTTON']
          create_view: boolean
          view_name: 'place-holder'
          """)

        self.assertIsInstance(test_config, dict)

        for key, value in iter(test_config.items()):
            self.assertIsInstance(key, str)
            self.assertIsInstance(value, dict)
            self._config_validation(value)
