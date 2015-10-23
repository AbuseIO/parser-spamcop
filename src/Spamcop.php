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

        $report = [ ];

        if ($this->parsedMail->getHeader('subject') == "[SpamCop] summary report") {
            $this->feedName = 'summary';

        } elseif ($this->parsedMail->getHeader('subject') == "[SpamCop] Alert") {
            $this->feedName = 'alert';

        } elseif (strpos($this->parsedMail->getHeader('from'), "@reports.spamcop.net") !== false) {
            // TODO detect spamvertized
            $this->feedName = 'spamreport';

            /*
             * This is a ARF mail with a single event
             *
             */
            if ($this->arfMail !== false) {
                //Seriously spamcop? Newlines arent in the CL specifications
                $this->arfMail['report'] = str_replace("\r", "", $this->arfMail['report']);

                preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/', $this->arfMail['report'], $regs);
                $report = array_combine($regs[1], $regs[2]);

                //Valueable information put in the body instead of the report, thnx for that Spamcop
                if (strpos($this->arfMail['message'], 'Comments from recipient') !== false) {
                    preg_match(
                        "/Comments from recipient.*\s]\n(.*)\n\n\nThis/s",
                        str_replace(array("\r", "> "), "", $this->arfMail['message']),
                        $match
                    );
                    $report['recipient_comment'] = str_replace("\n", " ", $match[1]);
                }

                // Add the headers from evidence into infoblob
                $parsedEvidence = new MimeParser();
                $parsedEvidence->setText($this->arfMail['evidence']);
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

                /*
                 * Sometimes Spamcop has a trouble adding the correct fields. The IP is pretty
                 * normal to add. In a last attempt we will try to fetch the IP from the body ourselves
                 */
                if (empty($report['Source-IP'])) {
                    preg_match(
                        "/Email from (?<ip>[a-f0-9:\.]+) \/ " . preg_quote($report['Received-Date']) . "/s",
                        $this->arfMail['message'],
                        $regs
                    );

                    if (!filter_var($regs['ip'], FILTER_VALIDATE_IP) === false) {
                        $report['Source-IP'] = $regs['ip'];
                    }
                }
            } elseif (strpos($this->parsedMail->getMessageBody(), '[ Offending message ]')) {
                /*
                 * This is a spamcop formatted mail with a single event
                 *
                 */
                $body = $this->parsedMail->getMessageBody();

                // Grab the message part from the body
                preg_match(
                    '/(\[ SpamCop V[0-9\.\]\ ]*+)\r?\n(?<message>.*)\r?\n\[ Offending message \]/s',
                    $body,
                    $matches
                );
                if (!empty($matches['message'])) {
                    $report['message'] = $matches['message'];
                }

                // Grab the Evidence from the body
                preg_match(
                    '/(\[ Offending message \]*+)\r?\n(?<evidence>.*)/s',
                    $body,
                    $matches
                );
                if (!empty($matches['evidence'])) {
                    $parsedEvidence = new MimeParser();
                    $parsedEvidence->setText($matches['evidence']);
                    $report['evidence'] = $parsedEvidence->getHeaders();
                }

                // Now parse the data from both extracts
                if (!empty($report['message']) && !empty($report['evidence'])) {
                    preg_match(
                        '/Email from (?<ip>[a-f0-9:\.]+) \/ (?<date>.*)\r?\n?\r\n/',
                        $report['message'],
                        $matches
                    );

                    if (!empty($matches['ip']) && !empty($matches['date'])) {
                        $report['Source-IP'] = $matches['ip'];
                        $report['Received-Date'] = $matches['date'];
                    }

                } else {
                    $this->warningCount++;
                }

            } else {
                $this->warningCount++;
            }

        } else {
            $this->warningCount++;
        }


        // If feed is known and enabled, validate data and save report
        if ($this->isKnownFeed() && $this->isEnabledFeed()) {
            // Sanity check
            if ($this->hasRequiredFields($report) === true) {
                // Event has all requirements met, filter and add!
                $report = $this->applyFilters($report);

                // Now we have our main datasets, we will create the events
                if ($this->feedName == 'summary') {
                    // Multi event message, with multiple rows in a table

                } elseif ($this->feedName == 'alert') {
                    // Multi event message, with on or more IP's in the body

                } elseif ($this->feedName == 'spamreport') {
                    // Single event message

                    $this->events[] = [
                        'source'        => config("{$this->configBase}.parser.name"),
                        'ip'            => $report['Source-IP'],
                        'domain'        => false,
                        'uri'           => false,
                        'class'         => config("{$this->configBase}.feeds.{$this->feedName}.class"),
                        'type'          => config("{$this->configBase}.feeds.{$this->feedName}.type"),
                        'timestamp'     => strtotime($report['Received-Date']),
                        'information'   => json_encode($report),
                    ];

                } elseif ($this->feedName == 'spamvertizedreport') {
                    // Single event message

                } else {
                    $this->warningCount++;
                }

            }
        }

        return $this->success();
    }
}
