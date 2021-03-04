require 'pp'
require 'yaml'
require 'csv'

# MIGRATION STATUS: Not done!
# Uncomment once this is done.
# raise 'Migration already performed.' # Don't run this. Kept for posterity

# Got this list from doing this in IRB
# YAML.load(File.open('skeletons/cve.yml')).each { |(key, _value)| puts key }
# Then order the keys in what you want.
def order_of_keys
  %w(
    CVE
    yaml_instructions
    curated_instructions
    curated
    reported_instructions
    reported_date
    announced_instructions
    announced_date
    published_instructions
    published_date
    description_instructions
    description
    bounty_instructions
    bounty
    reviews
    bugs
    repo
    fixes_vcc_instructions
    fixes
    vccs
    upvotes_instructions
    upvotes
    unit_tested
    discovered
    discoverable
    specification
    subsystem
    interesting_commits
    i18n
    sandbox
    ipc
    lessons
    mistakes
    CWE_instructions
    CWE
    CWE_note
    nickname_instructions
    nickname
  )
end

# Given a list of [{commit: '', note: ''},{commit: '', note: ''}]
# And a commit hash with a note.
# Either add it to the list if it's not there, or
# Add the note to the existing commit entry of the list
def combine_commit_list(commit_list, new_commit, new_note)
  new_list = if commit_list.map { |c| c['commit'] }.include?(new_commit)
    commit_list.map do |c|
      if c['commit'] == new_commit
        {
          'commit' => new_commit,
          'note'   => c['note'] + new_note
        }
      else
        c # no change
      end
    end
  else
    commit_list + [{ 'commit' => new_commit, 'note' => new_note }]
  end
  return new_list
end

# Remove anything from the commit list that is empty, then append one
# new one at the end.
def clean_commit_list(commit_list)
  new_list = commit_list.reject {|c| c['commit'].nil? || c['commit'].empty? }
  new_list + [{'commit' => '', 'note' => ''}]
end

# Going to start with the Munaiah data set. This is from Nuthan Munaiah's
# dissertation in 2020. To minimize size, we'll delete munaiah-data.csv after
# running this migration. Dig into Git history to find munaiah-data.csv

# headers:
# Year,CVE,Fix,# archeogit,,# SZZUnleashed,,# Common,,# archeogit Only,,# SZZUnleashed Only,,% Overlap
cves = {} # dictionary of CVE identifier to hash of to-be-YML data
skeleton = YAML.load(File.open('skeletons/cve.yml'), symbolize_names: false)
CSV.open('migrations/munaiah-data.csv').each do |row|
  cve = row[1].strip.upcase
  fix = row[2].strip
  vccs_from_archeogit = row[4].to_s.split ','
  vccs_from_szzunleashed = row[6].to_s.split ','

  cves[cve] ||= skeleton         # init to skeleton if not exists
  cves[cve]['CVE'] = cve          # set the CVE field
  cves[cve]['fixes'] ||= []
  cves[cve]['fixes'] = combine_commit_list(cves[cve]['fixes'], fix, '')
  cves[cve]['fixes'] = clean_commit_list(cves[cve]['fixes'])

  cves[cve]['vccs'] ||= []
  cves[cve]['vccs'] = combine_commit_list(cves[cve]['vccs'], vccs_from_archeogit, "Identified by archeogit. ")
  cves[cve]['vccs'] = combine_commit_list(cves[cve]['vccs'], vccs_from_szzunleashed, "Identified by SZZUnleashed. ")
  cves[cve]['vccs'] = clean_commit_list(cves[cve]['vccs'])

  # Generate the new YML, clean it up, write it out.
  yml_file = "cves/#{cve}.yml"
  File.open(yml_file, "w+") do |file|
    yml_txt = cves[cve].to_yaml[4..-1] # strip off ---\n
    stripped_yml = ""
    yml_txt.each_line do |line|
      stripped_yml += "#{line.rstrip}\n" # strip trailing whitespace
    end
    file.write(stripped_yml)
    print '.'
  end

end

puts 'Done!'
