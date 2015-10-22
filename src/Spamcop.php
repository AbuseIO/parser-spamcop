<?php

namespace AbuseIO\Parsers;

use PhpMimeMailParser\Parser as MimeParser;

class Spamcop extends Parser
{

    /**
     * Create a new Spamcop instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse attachments
     * @return Array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {

        $events = [ ];
        $report = [ ];

        if ($this->parsedMail->getHeader('subject') == "[SpamCop] summary report") {
            $this->feedName = 'summary';

        } elseif ($this->parsedMail->getHeader('subject') == "[SpamCop] Alert") {
            $this->feedName = 'alert';

        } elseif (strpos($this->parsedMail->getHeader('from'), "@reports.spamcop.net") !== false) {
            // This is a ARF mail with a single event
            $this->feedName = 'spamreport'; //TODO detect spamvertized

            if ($this->arfMail === false) {
                return $this->failed("Detected feed '{$this->feedName}' should be ARF, but received plain message.");
            }

            //Seriously spamcop? Newlines arent in the CL specifications
            $this->arfMail['report'] = str_replace("\r", "", $this->arfMail['report']);

            preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/', $this->arfMail['report'], $regs);
            $report = array_combine($regs[1], $regs[2]);

            //Valueable information put in the body instead of the report, thnx for that Spamcop
            if (strpos($this->parsedMail->getMessageBody(), 'Comments from recipient') !== false) {
                preg_match(
                    "/Comments from recipient.*\s]\n(.*)\n\n\nThis/s",
                    str_replace(array("\r","> "), "", $this->parsedMail->getMessageBody()),
                    $match
                );
                $report['recipient_comment'] = str_replace("\n", " ", $match[1]);
            }

            // Add the headers from evidence into infoblob
            $parsedEvidence = new MimeParser();
            $parsedEvidence->setText($this->arfMail['evidence']);

            //$fields['headers'] = [ ];
            $headers = $parsedEvidence->getHeaders();

            foreach ($headers as $key => $value) {
                if (is_array($value) || is_object(($value))) {
                    foreach ($value as $index => $subvalue) {
                        $report['headers']["${key}${index}"] = "$subvalue";
                    }
                } else {
                    $report['headers']["$key"] = $value;
                }
            }

            // Sometimes Spamcop has a trouble adding the correct fields. The IP is pretty
            // normal to add. In a last attempt we will try to fetch the IP from the body ourselves
            if (empty($report['Source-IP'])) {
                preg_match(
                    "/Email from (?<ip>[a-f0-9:\.]+) \/ ${report['Received-Date']}/s",
                    $this->parsedMail->getMessageBody(),
                    $regs
                );
                if (!filter_var($regs['ip'], FILTER_VALIDATE_IP) === false) {
                    $report['Source-IP'] = $regs['ip'];
                } else {
                    return $this->failed("Unabled to detect IP address for this event");
                }
            }

        } else {
            return $this->failed("Unabled to detect the report type from this notifier");
        }


        if (!$this->isKnownFeed()) {
            return $this->failed(
                "Detected feed {$this->feedName} is unknown."
            );
        }

        if (!$this->isEnabledFeed()) {
            return $this->success($events);
        }

        if (!$this->hasRequiredFields($report)) {
            return $this->failed(
                "Required field {$this->requiredField} is missing or the config is incorrect."
            );
        }

        $report = $this->applyFilters($report);


        // Now we have our main datasets, we will create the events
        if ($this->feedName == 'summary') {
            // Multi event message, with multiple rows in a table

        } elseif ($this->feedName == 'alert') {
            // Multi event message, with on or more IP's in the body

        } elseif ($this->feedName == 'spamreport') {
            // Single event message

            $event = [
                'source'        => config("{$this->configBase}.parser.name"),
                'ip'            => $report['Source-IP'],
                'domain'        => false,
                'uri'           => false,
                'class'         => config("{$this->configBase}.feeds.{$this->feedName}.class"),
                'type'          => config("{$this->configBase}.feeds.{$this->feedName}.type"),
                'timestamp'     => strtotime($report['Received-Date']),
                'information'   => json_encode($report),
            ];

            $events[] = $event;

        } elseif ($this->feedName == 'spamvertizedreport') {
            // Single event message

        } else {
            return $this->failed("Passed feedtype seems exist, but feedtype was not defined?!");
        }


        return $this->success($events);
    }
}

