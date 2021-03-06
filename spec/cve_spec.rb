require_relative 'spec_helper'
require 'yaml'

describe 'CVE yml file' do

  cve_ymls.each do |file|

    context "#{File.basename(file)}" do
      it 'is legal YAML' do
        expect(YAML.load(File.open(file))).to be
      end

      let(:vuln) { YAML.load(File.open(file)) }

      it('has all the proper keys')  do
        expect(vuln).to include('fixes')
        expect(vuln).to include('CVE')
        expect(vuln).to include('vccs')
      end

      it 'has valid 40-char git hashes and commit/note structure in fixes, vccs, and interesting_commits' do
        vuln['fixes'].each do |fix|
          expect(fix['commit'].to_s).to(match(/[0-9a-f]{40,}/).or(be_empty))
        end
        vuln['vccs'].each do |fix|
          expect(fix['commit'].to_s).to(match(/[0-9a-f]{40,}/).or(be_empty))
        end
        vuln['interesting_commits']['commits'].each do |fix|
          expect(fix['commit'].to_s).to(match(/[0-9a-f]{40,}/).or(be_empty))
        end
      end

      it 'has lessons properly formatted' do
        expect(vuln['lessons']['defense_in_depth']['applies']).to be(true).
                                                               or(be(false)).
                                                               or(be_nil)
        expect(vuln['lessons']['least_privilege']['applies']).to be(true).
                                                               or(be(false)).
                                                               or(be_nil)
        expect(vuln['lessons']['frameworks_are_optional']['applies']).to be(true).
                                                               or(be(false)).
                                                               or(be_nil)
        expect(vuln['lessons']['native_wrappers']['applies']).to be(true).
                                                               or(be(false)).
                                                               or(be_nil)
        expect(vuln['lessons']['distrust_input']['applies']).to be(true).
                                                               or(be(false)).
                                                               or(be_nil)
        expect(vuln['lessons']['security_by_obscurity']['applies']).to be(true).
                                                               or(be(false)).
                                                               or(be_nil)
        expect(vuln['lessons']['serial_killer']['applies']).to be(true).
                                                               or(be(false)).
                                                               or(be_nil)
        expect(vuln['lessons']['environment_variables']['applies']).to be(true).
                                                               or(be(false)).
                                                               or(be_nil)
        expect(vuln['lessons']['secure_by_default']['applies']).to be(true).
                                                               or(be(false)).
                                                               or(be_nil)
        expect(vuln['lessons']['yagni']['applies']).to be(true).
                                                               or(be(false)).
                                                               or(be_nil)
        expect(vuln['lessons']['complex_inputs']['applies']).to be(true).
                                                               or(be(false)).
                                                               or(be_nil)
      end

      it 'has an empty nickname or under 30 chars' do
        expect(vuln['nickname'].to_s.length).to be <= 30
      end

      context 'when curated at level 1, it must' do
        it 'have the CWE filled out' do
          if at_curation_level?(vuln, 1)
            expect(vuln['CWE'].to_s).not_to be_empty
          end
        end

        it 'have a description and mistakes made written' do
          if at_curation_level?(vuln, 1)
            expect(vuln['description'].to_s).not_to be_empty
            expect(vuln['mistakes']['answer'].to_s).not_to be_empty
          end
        end

        it 'have answers for unit_tested questions' do
          if at_curation_level?(vuln, 1)
            expect(vuln['unit_tested']['code']).to be(true).or(be(false))
            expect(vuln['unit_tested']['code_answer'].to_s).not_to be_empty
            expect(vuln['unit_tested']['fix']).to be(true).or(be(false))
            expect(vuln['unit_tested']['fix_answer'].to_s).not_to be_empty
          end
        end

        it 'have answers discovered and autodiscoverable' do
          if at_curation_level?(vuln, 1)
            expect(vuln['discovered']['answer'].to_s).not_to be_empty
            expect(vuln['discovered']['automated']).to be(true).or(be(false))
            expect(vuln['discovered']['contest']).to be(true).or(be(false))
            expect(vuln['discovered']['developer']).to be(true).or(be(false))
            expect(vuln['autodiscoverable']['answer_note'].to_s).not_to be_empty
            expect(vuln['autodiscoverable']['answer']).to be(true).or(be(false))
          end
        end

        it 'have answers for specification' do
          if at_curation_level?(vuln, 1)
            expect(vuln['specification']['answer_note'].to_s).not_to be_empty
            expect(vuln['specification']['answer']).to be(true).or(be(false))
          end
        end

        it 'have properly formatted subsystem names' do
          if at_curation_level?(vuln, 1)
            expect(vuln['subsystem']['answer'].to_s).not_to be_empty
            subsystem_str = Array[vuln['subsystem']['name']].join
            expect(subsystem_str).to match(/^[a-zA-Z\s0-9\_\-\@]+$/)
          end
        end

        it 'have answers for i18n' do
          if at_curation_level?(vuln, 1)
            expect(vuln['i18n']['note'].to_s).not_to be_empty
            expect(vuln['i18n']['answer']).to be(true).or(be(false))
          end
        end

        it 'have answers for ipc' do
          if at_curation_level?(vuln, 1)
            expect(vuln['ipc']['note'].to_s).not_to be_empty
            expect(vuln['ipc']['answer']).to be(true).or(be(false))
          end
        end
      end
    end
  end
end
