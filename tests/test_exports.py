import json
import tempfile
import unittest
from pathlib import Path
from watch.store import Store
from watch.exports import public_snapshot,domain_evaluation

class ExportTests(unittest.TestCase):
    def test_snapshot_omits_private_material(self):
        with tempfile.TemporaryDirectory() as d:
            db=Store(Path(d)/'db');db.ingest([{'domain':'maybank.example','synthetic':True}]);db.review('maybank.example','reviewing','unknown','Private note 123')
            db.report('maybank.example','Internal SOC','PRIVATE-REFERENCE','Private report')
            result=public_snapshot(db)
            self.assertNotIn('Private note',result);self.assertNotIn('PRIVATE-REFERENCE',result);self.assertIn('maybank[.]example',result)
    def test_domain_evaluation_accounts_for_benign_near_match(self):
        result=domain_evaluation();self.assertEqual(result['metrics']['n'],12)
        row=next(x for x in result['results'] if x['domain']=='boost-community.example')
        self.assertEqual(row['truth'],'benign');self.assertEqual(row['prediction'],'suspicious')
