<?php

namespace AbuseIO\Parsers;

use Ddeboer\DataImport\Reader;
use Ddeboer\DataImport\Writer;
use Ddeboer\DataImport\Filter;
use PhpMimeMailParser\Parser as MimeParser;
use Log;
use ReflectionClass;

class Spamcop extends Parser
{
    public $parsedMail;
    public $arfMail;

    /**
     * Create a new Blocklistde instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        $this->parsedMail = $parsedMail;
        $this->arfMail = $arfMail;
    }

    /**
     * Parse attachments
     * @return Array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        // Generalize the local config based on the parser class name.
        $reflect = new ReflectionClass($this);
        $configBase = 'parsers.' . $reflect->getShortName();

        Log::info(
            get_class($this) . ': Received message from: ' .
            $this->parsedMail->getHeader('from') . " with subject: '" .
            $this->parsedMail->getHeader('subject') . "' arrived at parser: " .
            config("{$configBase}.parser.name")
        );

        $events = [ ];

        if($this->parsedMail->getHeader('subject') == "[SpamCop] summary report") {
            $feedName = 'summary';

        } elseif ($this->parsedMail->getHeader('subject') == "[SpamCop] Alert") {
            $feedName = 'alert';

        } elseif (strpos($this->parsedMail->getHeader('from'), "@reports.spamcop.net") !== false) {
            // This is a ARF mail with a single event
            $feedName = 'spamreport'; //TODO detect spamvertized

            if ($this->arfMail === false) {
                return $this->failed("Detected feed '{$feedName}' should be ARF, but received plain message.");
            }

            //Seriously spamcop? Newlines arent in the CL specifications
            $this->arfMail['report'] = str_replace("\r", "", $this->arfMail['report']);

            preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/',$this->arfMail['report'], $regs);
            $fields = array_combine($regs[1],$regs[2]);

            //Valueable information put in the body instead of the report, thnx for that Spamcop
            if(strpos($this->parsedMail->getMessageBody(), 'Comments from recipient') !== false) {
                preg_match(
                    "/Comments from recipient.*\s]\n(.*)\n\n\nThis/s",
                    str_replace(array("\r","> "), "", $this->parsedMail->getMessageBody()),
                    $match
                );
                $fields['recipient_comment'] = str_replace("\n", " ", $match[1]);
            }

            // Add the headers from evidence into infoblob
            $parsedEvidence = new MimeParser();
            $parsedEvidence->setText($this->arfMail['evidence']);

            //$fields['headers'] = [ ];
            $headers = $parsedEvidence->getHeaders();

            foreach($headers as $key => $value) {
                if(is_array($value) || is_object(($value))) {
                    foreach($value as $index => $subvalue) {
                        $fields['headers']["${key}${index}"] = "$subvalue";
                    }
                } else {
                    $fields['headers']["$key"] = $value;
                }
            }

            // Sometimes Spamcop has a trouble adding the correct fields. The IP is pretty
            // normal to add. In a last attempt we will try to fetch the IP from the body ourselves
            if(empty($fields['Source-IP'])) {
                preg_match(
                    "/Email from (?<ip>[a-f0-9:\.]+) \/ ${fields['Received-Date']}/s",
                    $this->parsedMail->getMessageBody(),
                    $regs
                );
                if (!filter_var($regs['ip'], FILTER_VALIDATE_IP) === false) {
                    $fields['Source-IP'] = $regs['ip'];
                } else {
                    return $this->failed("Unabled to detect IP address for this event");
                }
            }

        } else {
            return $this->failed("Unabled to detect the report type from this notifier");
        }

        if (empty(config("{$configBase}.feeds.{$feedName}"))) {
            return $this->failed("Detected feed '{$feedName}' is unknown.");
        }

        $columns = array_filter(config("{$configBase}.feeds.{$feedName}.fields"));
        if (count($columns) > 0) {
            foreach ($columns as $column) {
                if (!isset($fields[$column])) {
                    return $this->failed(
                        "Required field ${column} is missing in the report or config is incorrect."
                    );
                }
            }
        }

        if (config("{$configBase}.feeds.{$feedName}.enabled") !== true) {
            return $this->success($events);
        }

        // Now we have our main datasets, we will create the events
        if ($feedName == 'summary') {
            // Multi event message, with multiple rows in a table

        } elseif ($feedName == 'alert') {
            // Multi event message, with on or more IP's in the body

        } elseif ($feedName == 'spamreport') {
            // Single event message

            $event = [
                'source'        => config("{$configBase}.parser.name"),
                'ip'            => $fields['Source-IP'],
                'domain'        => false,
                'uri'           => false,
                'class'         => config("{$configBase}.feeds.{$feedName}.class"),
                'type'          => config("{$configBase}.feeds.{$feedName}.type"),
                'timestamp'     => strtotime($fields['Received-Date']),
                'information'   => json_encode($fields),
            ];

            $events[] = $event;

        } elseif ($feedName == 'spamvertizedreport') {
            // Single event message

        } else {
            return $this->failed("Passed feedtype seems exist, but feedtype was not defined?!");
        }

        if (empty($events)) {
            return $this->failed(
                config("{$configBase}.parser.name") .
                " was unabled to collect any event(s) from the received email. Either corrupt sample or invalid config"
            );
        }

        Log::info(print_r($events, true));

        return $this->success($events);
    }

}
