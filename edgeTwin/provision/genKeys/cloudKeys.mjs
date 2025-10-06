import {createOrLoadKeys,createCertificate} from '../keyUtils/Ed25519Key.mjs';
import { join } from 'path';

const secureDir = '/secure/cloud/'
const privClientKeyFilePath = join(secureDir, 'keys', 'client.priv.key');
const pubClientKeyFilePath = join(secureDir, 'keys', 'client.pub.key');

const clientCAKeyPair = await createOrLoadKeys(privClientKeyFilePath, pubClientKeyFilePath);

