# wazuh-ecs

This project described the parsing of wazuh[HIDS] alert logs for elasticsearch with Elastic common schema using filebeat.

## Goal
Goal of the project is to parse wazuh alerts logs directly from wazuh manager as simple as possible with Elastic common schema for the alert data to be used with Elastic features including Elastic SIEM. 

## Warning
The parsing and conversion of alerts data with Elastic common schema is experimental. As much as possible ECS fields are parsed and added as initial release. 

## Assumption
The project assumes that [wazuh manager](https://documentation.wazuh.com/3.7/installation-guide/index.html), [elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/install-elasticsearch.html) are already installed. Wazuh official Installation guide and Elasticsearch official guide to be used for more details. [Filebeat](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-installation.html) to be installed in the wazuh management server. 

## Data parsing
Wazuh alerts data which in JSON format are to be read and decoded using structured and logging and multiline options with filebeat. These configuration options collect encoded JSON objects as a string spanning multiple lines.

```
multiline.pattern: '^{'
multiline.negate: true
multiline.match: after
```
Filebeat processors are used in decoding the JSON message into structured JSON objects and uniform naming convention with prefix as “wazuh” will be used across all the data parsed with wazuh alerts. 

```
Processor:
    - decode_json_fields:
        fields: ['message']
        target: "wazuh"
    - drop_fields:
        fields: ['message']
```

## ECS parsing
straightforward mapping of the original fields in the wazuh alert data to ECS using ecs-mapper.
[ecs-mapper](https://github.com/elastic/ecs-mapper) is a tool to generate starter pipelines of each flavor, to help you get started quickly in mapping your event sources to ECS.

wazuh-ECS-mapping template sheet is maintained for mapping of alert data into ECS and used with ecs-mapper tool in generating pipelines. 

FIlebeat is configured with a configuration file that decodes multiline json alerts from wazuh and uses processors to decode and map the alert data into ECS and common naming convention. 

## Field descriptions

| Field format | Description                                                    |
|--------------|----------------------------------------------------------------|
| host.*       | Details of server running the filebeat [usually wazuh manager] |
| agent.*      | Wazuh agent details                                            |
| event.*      | events related to wazuh alerts mapped with ECS                 |
| rule.*       | wazuh rule details mapped to ECS                               |
| wazuh.*      | original data fields from wazuh alert                          |


