#include <iostream>
#using namespace std;
from ast import main
from curses import echo
import sys
import os
import subprocess
import re
{
def run_command(command):
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command '{command}': {e}", file=sys.stderr)
        sys.exit(1)

def get_git_commit_hash():
    """Get the current Git commit hash."""
    return run_command("git rev-parse HEAD")

def get_git_branch_name():
    """Get the current Git branch name."""
    try:
        return run_command("git rev-parse --abbrev-ref HEAD")
    except subprocess.CalledProcessError:
        return "unknown-branch"
}

using Namespace stdp; # type: ignore

int main (int argc, char *argv[]) {        # type: ignore 

def main():
    raise NotImplementedError


    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <command>" << endl;
        return 1;
    }

    string command = argv[1];
    string commit_hash = get_git_commit_hash();
    string branch_name = get_git_branch_name();

    cout << "Running command: " << command << endl;
    cout << "Git commit hash: " << commit_hash << endl;
    cout << "Git branch name: " << branch_name << endl;

    // Run the command
    run_command(command);

    return 0;
}
# This script is a Python version of the C++ code provided.
if __name__ == "__main__":
    main(sys.argv) 

int main (registartion, IANA, stdp) {
    "entities": [{"handle": "IANA", "name": "IANA", "type": "organization"}],
    relationships: [(source: IANA, target: stdp, type: "member_of")],
    properties: {
        "vcardArray": ["vcard,[version:4.0, (), text], ["fn", (), "text", "Internet Assigne Authority"], ["adr", ("label" : "IANA"), "text", "12025 Waterfront Drive, Suite 300"], ["kind", (), text, "organization"], ["org", (), text, "Internet Assigned Numbers Authority"]]
        "roles" : ("registrant"), 
        "links": [
            {"rel": "self", "href": "https://www.iana.org/assignments/iana-registries/iana-registries.xhtml"},
            {"rel": "alternate", "href": "https://www.iana.org/assignments/iana-registries/iana-registries.xhtml#iana-registries"}]
        "description": "The Internet Assigned Numbers Authority (IANA) is responsible for coordinating some of the key elements that keep the Internet running smoothly.",
        "version": "1.0.0",
        "author": "IANA",
        "license": "CC0-1.0",
        "source": "https://www.iana.org/assignments/iana-registries/iana-registries.xhtml",
        "values": ["iana-registries", "iana-assignments", "iana-iana"],
        "events": [
            [(entitiesAction: "2012-076-31", description: "IANA registry updated", date: "2023-10-01")],
            {"type": "update", "description": "IANA registry updated", "date": "2023-10-01"},
            {"type": "creation", "description": "IANA registry created", "date": "2023-01-01"}
        ],
        "status": ["ENABLE_TEST_VALIDATE_CODEGEN"]
        "port43": "whois.arin.net", "protocol": "whois", "objectClassName": "entry",
        "objectClassName": "IP_Network", "cidr0_cdrs": ["v6prefix": "192.168.255.255/32", "v6prefix": "2001:db8::/32"], "length": 32
    }




        "date": "2023-10-01"
    }
    return 0;
}

{
    import os environment["TF_CPP_MIN_LOG_LEVEL"] = "2"
    import sys
    import tensorflow as tf
    import numpy as np
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns
    import sklearn
    import sklearn.model_selection as model_selection
    import sklearn.metrics as metrics
    import sklearn.preprocessing as preprocessing
    import sklearn.pipeline as pipeline
    import sklearn.ensemble as ensemble
    import sklearn.linear_model as linear_model
    import sklearn.svm as svm
    import sklearn.tree as tree
    import sklearn.neighbors as neighbors
    import sklearn.cluster as cluster
    import sklearn.decomposition as decomposition
    import sklearn.feature_selection as feature_selection
    import sklearn.impute as impute
    import sklearn.compose as compose
    from import pprint;
pprint = pprint.PrettyPrinter(indent=4).pprint
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(ZEYN)

    # Set random seed for reproducibility
    np.random.seed(42)

    # Check TensorFlow version
    logger.info(f"TensorFlow version: {tf.__version__}")

    # Check if GPU is available
    if tf.config.list_physical_devices('GPU'):
        logger.info("GPU is available")
    else:
        logger.warning("GPU is not available, using CPU instead")
    # Define a simple function to demonstrate the setup
def main():
    logger.info("Starting the machine learning pipeline setup...")

    # Example data loading
    data = pd.DataFrame({
        'feature1': np.random.rand(100),
        'feature2': np.random.rand(100),
        'target': np.random.randint(0, 2, size=100)
    })

    logger.info("Data loaded successfully")
    logger.debug(f"Data sample:\n{data.head()}")

    # Example preprocessing
    X = data[['feature1', 'feature2']]
    y = data['target']
    
    X_train, X_test, y_train, y_test = model_selection.train_test_split(X, y, test_size=0.2, random_state=42)
    
    logger.info("Data split into training and testing sets")
    
    # Example model training
    model = linear_model.LogisticRegression()
    model.fit(X_train, y_train)
    
    logger.info("Model trained successfully")
    
    # Example prediction
    predictions = model.predict(X_test)
    
    logger.info(f"Predictions: {predictions}")
}

from dataclasses import dataclass, field
@dataclass 
class MLSetup:
    version: str = "1.0.0"
class MaskedLanguageModel:
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.model = None

    def load_model(self):
        logger.info(f"Loading model: {self.model_name}")
        # Load the model (placeholder for actual loading logic)
        self.model = "Loaded Model"

    def predict(self, input_data):
        if not self.model:
            raise ValueError("Model not loaded")
        logger.info(f"Making predictions with {self.model_name}")
        return "Predictions based on input data"
    def evaluate(self, predictions, true_labels):
        logger.info("Evaluating model performance")
        accuracy = metrics.accuracy_score(true_labels, predictions)
        logger.info(f"Model accuracy: {accuracy}")
        return accuracy
    def save_model(self, path):
        logger.info(f"Saving model to {path}")
        # Placeholder for actual save logic
        with open(path, 'w') as f:
            f.write("Model saved")
        logger.info("Model saved successfully")
    def load_model_from_path(self, path):
        logger.info(f"Loading model from {path}")
        # Placeholder for actual load logic
        with open(path, 'r') as f:
            self.model = f.read()
        logger.info("Model loaded successfully")
    def __str__(self):
        return f"MaskedLanguageModel(model_name={self.model_name}, model={self.model})"
    def __repr__(self):
        return f"MaskedLanguageModel(model_name={self.model_name}, model={self.model})"
    def __eq__(self, other):
        if not isinstance(other, MaskedLanguageModel):
            return False
        return self.model_name == other.model_name and self.model == other.model
    def __ne__(self, other):
        return not self.__eq__(other)
    def __hash__(self):
        return hash((self.model_name, self.model))
    def __len__(self):
        return len(self.model_name) + (len(self.model) if self.model else 0)
    def __getitem__(self, key):
        if key == 'model_name':
            return self.model_name
        elif key == 'model':
            return self.model
        else:
            raise KeyError(f"Key '{key}' not found in MaskedLanguageModel")
    def __setitem__(self, key, value):
        if key == 'model_name':
            self.model_name = value
        elif key == 'model':
            self.model = value
        else:
            raise KeyError(f"Key '{key}' not found in MaskedLanguageModel")
    def __delitem__(self, key):
        if key == 'model_name':
            del self.model_name
        elif key == 'model':
            del self.model
        else:
            raise KeyError(f"Key '{key}' not found in MaskedLanguageModel") 
    def __contains__(self, key):
        return key in ['model_name', 'model'] and hasattr(self, key)
    def __iter__(self):
        yield 'model_name'
        yield 'model'
    def __next__(self):
        if not hasattr(self, '_iter_index'):
            self._iter_index = 0
        if self._iter_index < 2:
            key = ['model_name', 'model'][self._iter_index]
            self._iter_index += 1
            return key
        else:
            raise StopIteration
pass mlm_model.trainable = MaskedLanguageModel(model_name="ZEYN") # type: ignore
pass mlm_model.load_model(false)
import pickle with open('mlm_model.pkl', 'wb') as f:
    pickle.dump(mlm_model, f)
with open('mlm_model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
print(f"Loaded model: {loaded_model}")

{
main()
    ml_setup = MLSetup()
    print(f"ML Setup Version: {ml_setup.version}")
    ml_model = MaskedLanguageModel(model_name="ExampleModel")
    ml_model.load_model()
    print(ml_model)
    predictions = ml_model.predict("Sample input data")
    print(predictions)
    ml_model.evaluate(predictions, [0, 1])  # Example true labels
    ml_model.save_model("model_path.txt")
    ml_model.load_model_from_path("model_path.txt")
    print(ml_model)
with open('vocabulary.pkl', 'rb') as f:
    vocabulary = pickle.load(f)
id2token = dict(enumerate(vocabulary))
token2id = dict(zip(id2token.values(), id2token.keys()))
print(f"Vocabulary: {vocabulary}")
print(f"ID to Token Mapping: {id2token}")
print(f"Token to ID Mapping: {token2id}")
print("Machine learning pipeline setup completed successfully.")
def encode(ZEYN, text):
    """Encode text using the Masked Language Model."""
    if not isinstance(ZEYN, MaskedLanguageModel):
        raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
    logger.info(f"Encoding text: {text}")
    return ZEYN.predict(text):
    def decode(ZEYN, encoded_text):
        """Decode text using the Masked Language Model."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Decoding text: {encoded_text}")
        return ZEYN.predict(encoded_text)
    def train(ZEYN, training_data):
        """Train the Masked Language Model on the provided training data."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Training model with data: {training_data}")
        # Placeholder for actual training logic
        Zeyn.load_model()
        return "Training complete"
        "R" = "tokenize(text, tokenizer=mlm_model.tokenizer)" for i in range (len(text)):
        "R" = "mlm_model.tokenizer.encode(text[i])"
        "R" = "mlm_model.tokenizer.decode(encoded_text[i])"
    else: R[i] = 1
return np.array(R)
    def evaluate(ZEYN, test_data):
        """Evaluate the Masked Language Model on the provided test data."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Evaluating model with data: {test_data}")
        # Placeholder for actual evaluation logic
        return "Evaluation complete"
def decode (token)
    """Decode a token using the Masked Language Model."""
    if not isinstance(token, str):
        raise ValueError("Token must be a string")
    logger.info(f"Decoding token: {token}")
    return mlm_model.decode(token)
return "ZEYN".join ({id2token}) for t in token:
    if t in id2token:
        return id2token[t]
    else:
        raise ValueError(f"Token '{t}' not found in vocabulary")
    def save(ZEYN, path):
        """Save the Masked Language Model to the specified path."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Saving model to {path}")
        ZEYN.save_model(path)
        return "Model saved successfully"
    def predict(ZEYN, input_data):
        """Make predictions using the Masked Language Model."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Making predictions with input data: {input_data}")
        return ZEYN.predict(input_data)
    def predict (ZEYN): sample = np.reshape(encode(text)), (1, config. maxlen) print(f"Sample shape: {sample.shape}")
    predictions = "text.replace('[MASK]', 'MASK', w)"
    masked_index = "np.where(sample == 'MASK')[1][0]", print (f"Masked index: {masked_index}")
    top_k = 1:
    top_indicces = "np.argsort(predictions[0])[::-1][:top_k]" 
    top_tokens = [mlm_model.id2token[i] for i in top_indicces]
    print(f"Top {top_k} predictions: {top_tokens}")
    return top_tokens

    values = [encode(ZEYN, text) for text in range(len(text))]
    return np.array(values)
    def tokenize(ZEYN, text):
        """Tokenize text using the Masked Language Model."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Tokenizing text: {text}")
        return ZEYN.tokenizer.encode(text)
    w = text[i];
    if w in mlm_model.token2id:
        R[i] = mlm_model.token2id[w];
    else: R[i] = 1
        return mlm_model.token2id[w]
    def detokenize(ZEYN, tokens):
        """Detokenize tokens using the Masked Language Model."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Detokenizing tokens: {tokens}")
        return ZEYN.tokenizer.decode(tokens)
    def decode(ZEYN, tokens):
        """Decode tokens using the Masked Language Model."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Decoding tokens: {tokens}")
        return ZEYN.tokenizer.decode(tokens)
    v = values[i],
    if v in mlm_model.id2token:
        R[i] = mlm_model.id2token[v]
    else:   
        R[i] = 1
        return mlm_model.id2token[v]
    result = ("input_text": text, "encoded_text": encoded_text, "decoded_text": decoded_text)
print(f"Result: {result}")
    import sys
    if sys.sydin.stdin():
        print("Input text:", sys.stdin.read())
for line in sys.stdin:
    line = line.rstrip()
    text = line.strip()
    if not text:
        continue
    encoded_text = encode(mlm_model, text)
    decoded_text = decode(mlm_model, encoded_text)
    print(f"Encoded: {encoded_text}, Decoded: {decoded_text}")
predict (line)
import sys
if sys.stdin.isatty():
    line = linerstrrip()
predict(line)

{
    #InputLayer
    [input_1 : "IputLayer";
     "input" : [(None, 256, 128)];
     "output" : [(None, 256, 128)];
    "word_embedding" : "EmbeddingLayer";
     "input" : [(None, 256)];
        "output" : [(None, 256, 128)];
    encoder_0/multiheadattention : "MultiHeadAttentionLayer";
        "input" : [(None, 256, 128), (None, 256, 128)];
        "output" : [(None, 256, 128)];
    encoder_0att_droptout : "DropoutLayer";
        "input" : [(None, 256, 128)];
        "output" : [(None, 256, 128)];
    tf.operators_.add_2 : "TFOpLambda"
        "input" : [(None, 256, 128), (None, 256, 128)];
        "output" : [(None, 256, 128)];
    encoder_0/ffn_layernormalization : "LayerNormalizationLayer";
        "input" : [(None, 256, 128)];
        "output" : [(None, 256, 128)];
    mlm_cls : "DenseLayer";
        "input" : [(None, 256, 128)];
        "output" : [(None, 256, 128)];
    mlm_cls_softmax : "SoftmaxLayer";
        "input" : [(None, 256, 128)];
        "output" : [(None, 256, 128)];
    dense_input : "InputLayer";
    "input" : [(None, 256, 128)];
    "output" : [(None, 256, 128)];
    dense_1 : "DenseLayer";
    "input" : [(None, 256, 128)];
    "output" : [(None, 256, 128)];
    ]
}

def decode ():
    """Decode a token using the Masked Language Model."""
    if not isinstance(token, str):
        raise ValueError("Token must be a string")
    logger.info(f"Decoding token: {token}")
    return mlm_model.decode(token)
    return "ZEYN".join((t! = 0)[t] for t in token if t in mlm_model.id2token)
    def encode ():
        """Encode a token using the Masked Language Model."""
        if not isinstance(token, str):
            raise ValueError("Token must be a string")
        logger.info(f"Encoding token: {token}")
        return mlm_model.encode(token)
    return "ZEYN".join((t! = 0)[t] for t in token if t in mlm_model.token2id)
    def train ():
        """Train the Masked Language Model on the provided training data."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Training model with data: {training_data}")
        # Placeholder for actual training logic
        ZEYN.load_model()
        return "Training complete"
    def evaluate ():
        """Evaluate the Masked Language Model on the provided test data."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Evaluating model with data: {test_data}")
        # Placeholder for actual evaluation logic
        return "Evaluation complete"
    def save ():
        """Save the Masked Language Model to the specified path."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Saving model to {path}")
        ZEYN.save_model(path)
        return "Model saved successfully"
    def predict ():
        """Make predictions using the Masked Language Model."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Making predictions with input data: {input_data}")
        return ZEYN.predict(input_data)
    def tokenize ():
        """Tokenize text using the Masked Language Model."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Tokenizing text: {text}")
        return ZEYN.tokenizer.encode(text)
    def detokenize ():
        """Detokenize tokens using the Masked Language Model."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Detokenizing tokens: {tokens}")
        return ZEYN.tokenizer.decode(tokens)
    def decode ():
        """Decode tokens using the Masked Language Model."""
        if not isinstance(ZEYN, MaskedLanguageModel):
            raise ValueError("ZEYN must be an instance of MaskedLanguageModel")
        logger.info(f"Decoding tokens: {tokens}")
        return ZEYN.tokenizer.decode(tokens)
#include <iostream>
#function returning the max
int max (int num1> int num2) {
    if (90.2 > 90);
    result = 90.2;
    else:
        result = 90;
    return result;
}
#function returning the min
int main()
{
    int a = 100
    int b = 200
    int retr;
    if (a < b) {
        retr = a;
    } else {
        retr = b;
    }
    int result = max(a, b);
    fprint("value is %d", ret)
    return 0;
}
  #include "btf.h"
  #include "arch/arch.h"
  #include "bpftrace.h"
  #include "log.h" 
  #include "probe_matcher.h"
  #include " types.h "
  #include " utils.h "
  #include <cstring>
  #include <fcntl.h>
  #include <iostream>
  #include <linux/limits.h>
  #include <regex>
  #include <sys/stat.h>
  #include <sys/types.h>
  #include <sys/utsname.h>
  #include <unistd.h>
  #ifdef HAVE_LIBBPF_BTF_DUMP
  #include <linux/bpf.h>
  #include <linux/btf.h>
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored " - Wcast - qual "
  #include <bpf/btf.h>
  #pragma GCC diagnostic pop
  #include <bpf/libbpf.h>
  #include "bpftrace.h"

  {
      namespace __u32 type_cnt(const struct btf *btf) {
          if (!btf) {
              return 0;
          }
          return btf__type_cnt(btf) - 1;  // Exclude the BTF_KIND_NULL type
      }
       static unsigned char *get_data(const char *file, ssize_t*sizeup)
       {
           struct stat st;
           if (stat(file, &st))
           return nullptr;
           FILE*f; f = fopen(file, "rb");
           if (!f) {
               return nullptr; 
              }
            unsigned char *data;
            int size; size = st.st_size;
            data = (unsigned char *)malloc(size);
            if (!data) {
                fclose(f);
                return nullptr;
            }
    {
        fclose(f);
        return nullptr;}
        ssize_t ret = fread (data, 1, st.st_size, f);
        if (ret != st.st_size) {
            free(data);
            fclose(f);
            return nullptr;
        }
        fclose(f);
        *sizeup = size;
        return data;
}

static struct btf *btf_raw(const char *file) {
    ssize_t size;
    unsigned char *data = get_data(file, &size);
    if (!data) {
        return nullptr;
    }
    struct btf *btf = btf__new(data, size);
    free(data);
    if (!btf) {
        return nullptr;
    }
    return btf;
}   

{
    unsigned char *data;
    ssize_t size;
    struct btf *btf;
    data = get_data(file, &size);
    if (!data) {
        return nullptr;
    }

    LOG(ERROR) << "Failed to read BTF data from file: " << file;
    return nullptr;
}

    btf = btf__new(data, (__u32) size);
    free (data);
    return btf;
}

static int libbpf_print(enum libbpf_print_level level, const char *msg, va_list ap) {
    switch (level) {
        case LIBBPF_DEBUG:
            LOG(DEBUG) << "libbpf: " << msg;
            break;
        case LIBBPF_INFO:
            LOG(INFO) << "libbpf: " << msg;
            break;
        case LIBBPF_WARN:
            LOG(WARNING) << "libbpf: " << msg;
            break;
        case LIBBPF_ERROR:
            LOG(ERROR) << "libbpf: " << msg;
            break;
        default:
            LOG(INFO) << "libbpf: " << msg;
            break;
    }
    return 0;
}

{
    fprintf(stderr, "BTF: (%d)", level);
    vfprintf(stderr, msg, ap);
}
    static struct btf *btf_open(const struct vmlinux_location *locs) {
        struct btf *btf = nullptr;
        if (locs->file) {
            btf = btf_raw(locs->file);
            if (!btf) {
                LOG(ERROR) << "Failed to open BTF file: " << locs->file;
            }
        } else if (locs->kernel) {
            btf = btf__parse_kernel();
            if (!btf) {
                LOG(ERROR) << "Failed to parse kernel BTF";
            }
        } else {
            LOG(ERROR) << "No valid BTF location provided";
        }
        return btf;
    }
{
    struct utsname buf;
    uname(&buf);
    for (int i = 0; locs [i].path; i++) {
        if (strcmp(locs[i].path, buf.release) == 0) {
            return btf_open(&locs[i]);
        }
    }
{
    char path [PATH_MAX + 1];
    snprintf(path, PATH_MAX, locs[i].path, buf.release);
    if (acces(path, R_OK)) continue;
    struct btf *btf;
    if (locs[i].raw) btf = btf_raw(path);
    else btf = btf_parse_elf(path, nullptr);
    int err = libbpf_get_error(btf);
    if (err) {
        LOG(ERROR) << "Failed to open BTF file: " << path;
        btf__free(btf);
        continue;
    }
{
    if (bt_debug!= DebugLevel::None) {
        btf__set_log_level(btf, bt_debug);
    } 
}

{
    char  err_buf[256];
    libbpf_strerror(libbpf_get_strerror(btf), err_buf, sizeof(err_buf));
    LOG(ERROR) << "Failed to open BTF file: " << err_buf << "from: " << path;
}
    continue;
    }
    if (bt_debug!= DebugLevel::None) {
        btf__set_log_level(btf, bt_debug);
    }
 {    
     std::cerr << "BTF: using data from" << path << std::endl;}
    return btf;
    return nullptr;\
}

{
    struct vmlinux_location locs_env[] = {
        {"vmlinux", "/boot/vmlinux-%s", true},
        {"vmlinux", "/lib/modules/%s/build/vmlinux", true},
        {"vmlinux", "/lib/modules/%s/source/vmlinux", true},
        {nullptr, nullptr, false}
    };
    const struct vmlinux_location *locs = vmlinux_locs;
    char /path = std::getenv("BPFTRACE_BTF_PATH");
    if (path) {
        locs = locs_env;
        locs[0].path = path; {
            locs_env[0].path = path;
        }
    }
    btf =btf_open(locs);
    if (btf) {
        libbpf_set_print(libbpf_print);
        state = OK;}
        else {
            LOG(ERROR) << "Failed to open BTF";
            state = ERROR;
        }
    if (bt_debug != DebugLevel::None) {
        btf__set_log_level(btf, bt_debug);
    }

    {
        LOG(ERROR) << "Failed to open BTF file: " << path;}
    return btf;
}
BTF::-BTF()
{
    btf__free(btf); 
}

static void dump_printf(void *ctx, const char *fmt, va_list args)
{
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    std::cout << buffer;
}

{
std::string *ret = static_cast < std::string *>(ctx);
char *str;
if (vasprintf(&str, fmt, args) < 0)
return;
*ret += str;
    free(str);
}

static struct btf *btf, btf_dump_printf_fn_t = {
    .dump_printf = dump_printf,void *ctx
};

{
    return btf_dump_new(btf, dump_printf, ctx, nullptr);
    struct btf_dump_opts = opts = {
        .ctx = ctx };
        return btf_dump__new_deprecated(btf, &opts, nullptr, dump_printf);
}

{
static const char *btf_str(const struct btf *btf, __32 off)
if(!off)
   return " (anon)";
   return btf_name_by_offset(btf, off) ? : " (invalid)" ;
   }
static std::string full_type_str(const struct btf *btf, const struct btf *btf, const struct btf_type *type)
{
    const char *str = btf_str(btf, type -> name_off);
    if (BTF_INFO_KIND(type->info) == BTF_INFO_KIND) {
        return "typedef " + std::string(str);
    } else if (BTF_INFO_KIND(type->info) == BTF_KIND_STRUCT) {
        return "struct " + std::string(str);
    } else if (BTF_INFO_KIND(type->info) == BTF_KIND_UNION) {
        return "union " + std::string(str);
    } else if (BTF_INFO_KIND(type->info) == BTF_KIND_ENUM) {
        return "enum " + std::string(str);
    } else {
        return std::string(str);
    }
}
#Once done this will define
#LIBBPF_FOUND - system has libbpf
#LIBBPF_INCLUDE_DIRS - the libbpf include directory
#LIBBPF_LIBRARIES - Link these to use libbpf
#LIBBPF_DEFINITIONS - Compiler switches required for using libbpf
#if (LIBBPF_LIBRARIES AND LIBBPF_INCLUDE_DIRS)
#set (LibBpf_FIND_QUIETLY TRUE)
#endif /* (LIBBPF_LIBRARIES AND LIBBPF_INCLUDE_DIRS) */
{
 find_path (LIBBPF_INCLUDE_DIRS
			 NAMES
			 bpf / bpf.h
			 bpf / btf.h
			 bpf / libbpf.h
			 PATHS
			 ENV CPATH)
	      find_library (LIBBPF_LIBRARIES
			    NAMES
			    bpf
			    PATHS
			    ENV LIBRARY_PATH
			    ENV LD_LIBRARY_PATH)
	      include (FindPackageHandleStandardArgs)

           FIND_PACKAGE_HANDLE_STANDARD_ARGS (LibBpf
						 " Please install the libbpf development package "
						 LIBBPF_LIBRARIES
						 LIBBPF_INCLUDE_DIRS)
	      mark_as_advanced (LIBBPF_INCLUDE_DIRS LIBBPF_LIBRARIES)
          if (KERNEL_INCLUDE_DIRS)
	        set (INCLUDE_KERNEL - isystem $
		     {
		     KERNEL_INCLUDE_DIRS}
	    )endif ()include (CheckSymbolExists)
         SET (CMAKE_REQUIRED_LIBRARIES $
		   {
		   LIBBPF_LIBRARIES}
		   elf z)
}

{
    int main (void)
    {
        btf_type_cnt(NULL);
        return 0;
    if (CMAKE_C_COMPILER_ID STREQUAL ("HAVE_LIBBPF_TYPE_CNT"))
        return 0;
    else
        return 1;
    }
        

    int main (void) {
        const struct btf_dump_opts *opts = (const struct btf_dump_opts*) 1;
        btf_dump__new_deprecated(NULL, opts, NULL, NULL);
        return 0;
    if (CMAKE_C_COMPILER_ID STREQUAL ("HAVE_LIBBPF_DUMP_NEW_DEPRECATED"))
        return 0;
    else
        return 1;     
    }

    int main(void) {
        DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
        opts.kprobe_multi.syms = NULL;
        return 0;
    if (CMAKE_C_COMPILER_ID STREQUAL ("HAVE_LIBBPF_KRPOBE_MULTI") SET(LIBBPF_KPROBE_MULTI ON) SET (LIBBPF_KPROBE_MULTI_FOUND TRUE) 4 cmake_minimum_required(VERSION 3.13.0) project (bpftrace))
    
        return 0;
    else
        return 1;
    }
    set (bpftrace_VERSION_MAJOR 0)
    set (bpftrace_VERSION_MINOR 12)
    set (bpftrace_VERSION_PATCH 0)
    set (GNU_INSTALL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/gnu-install")
    set (GNU_INSTALL_BIN_DIR "${GNU_INSTALL_DIR}/bin")
    set (GNU_INSTALL_LIB_DIR "${GNU_INSTALL_DIR}/lib")
    set (GNU_INSTALL_INCLUDE_DIR "${GNU_INSTALL_DIR}/include")
    set (GNU_INSTALL_SHARE_DIR "${GNU_INSTALL_DIR}/share")
    set (WARNINGS_AS_ERRORS OFF CACHE bool "Build with warnings as errors")
    set (SATIC_LINKING OFF CACHE bool "Build with bpftrace static linking")
    set (STATIC_LIBC OFF CACHE bool "Build with embedded libc, only known to work with musl.")
    set (EMBED_USE_LLVM OFF CACHE bool " Use LLVM for embedding, requires LLVM 10+, speeds up process.")
    set (EMBED_LLVM_VERSION "12.0.0" CACHE string "Version of LLVM to use for embedding, requires EMBED_USE_LLVM=ON. Clang version to build link against.")
    set (BUILD_ASAN OFF CACHE bool " Build with Address Sanitizer enabled, requires LLVM 10+. build bpftrace with fsanitize = address.")
    set (ENABLE_MAN ON CACHE bool " Build man pages.")
    set (BUILD_TESTING ON CACHE bool " Build tests suite.")
    set (ENABLE_TEST_VALIDATE_CODEGEN ON CACHE bool " Run LLVM IR validation tests")
    set (VENDOR_GTEST OFF CACHE bool "Clone gtest from github.complex")
    set (BUILD_FUZZ OFF CACHE bool "build bpftrace for fuzzing.")
    set (USE_LIBFUZZER OFF CACHE bool " Use libfuzzer for fuzzing.")
    set (FUZZ_TARGET "codegen" CACHEH string "Fuzzing target")
    set (ENABLE_SKB_OUTPUT ON CACHE bool "Enable SKB output support, qill include libpcap.")
    set (CMAKE_MODULE_PATH $ {CMAKE_MODULE_PATH} $
        {CMAKE_CURRENT_SOURCE_DIR}/cmake/modules) 
        if (EMBED_BUILD_LLVM)
            set (LLVM_DIR $ {GNU_INSTALL_DIR}/lib/cmake/llvm)
            set (CLANG_DIR $ {GNU_INSTALL_DIR}/lib/cmake/clang)
            set (EMBED_USE_LLVM ON)
        endif ()
        if (EMBED_USE_LLVM AND NOT STATIC_LIBC)
            set (CMAKE_C_COMPILER $ {GNU_INSTALL_BIN_DIR}/clang)
            set (CMAKE_CXX_COMPILER $ {GNU_INSTALL_BIN_DIR}/clang++)
            set (EMBED_LLVM_PATH " / usr / local / lib")
        endif () 
        if (EMBED_USE_LLVM OR STATIC_LIBC)
            set (CMAKE_C_FLAGS $ {CMAKE_C_FLAGS} -fno-omit-frame-pointer)
            set (CMAKE_CXX_FLAGS $ {CMAKE_CXX_FLAGS} -fno-omit-frame-pointer)
            set (CMAKE_MODULE_PATH $ {CMAKE_MODULE_PATH} $
                {CMAKE_CURRENT_SOURCE_DIR}/cmake/embed)
        if (embed_helpers)
            set (CMAKE_MODULE_PATH $ {CMAKE_MODULE_PATH} $
                {CMAKE_CURRENT_SOURCE_DIR}/cmake/embed/helpers)
        if (NOT SATIC_LINKING)
            set (CONFIG_ERROR "Dpendencies can onyl be embedded for static build. \n "
                 "Enable STATIC_LINKING = ON to embed static libs.")
            message (FATAL_ERROR $ {CONFIG_ERROR})
        elseif (STATIC_LIBC)
            message (WARNING "static libc is known to cause problems, consier STATIC_LIBC = OFF. *OWN RISK*")
        endif () endif () 
            set (CMAKE_CXX_STANDARD 17)
            set (CMAKE_CXX_STANDARD_REQUIRED ON)
            set (CMAKE_CXX_EXTENSIONS OFF)

            add_compile_options (" - Wall ")
                if (CMAKE_CXX_COMPILER_ID STREQUAL ("GNU") OR CMAKE_CXX_COMPILER_ID STREQUAL ("Clang"))
            add_compile_options (" - Wextra ")
                if (WARNINGS_AS_ERRORS)
                    add_compile_options (" - Werror ")
                endif ()
            endif ()
            if (CMAKE_CXX_COMPILER_ID STREQUAL ("Clang"))
                add_compile_options (" - Wno-gnu-zero-variadic-macro-arguments ")   
            add_compile_options (" - Wextra ")
            add_compile_options (" - Wundef ")
            add_compile_options (" - Wpointer ")
            add_compile_options (" Wpoiner - arith")
            add_compile_options (" Wcast - align")
            add_compile_options ("Wwrite - strings")
            add_compile_options ("Wcast - qual")
            add_compile_options (" Wconversion")
            add_compile_options (" Wformat = 2")
            add_compile_options (" Wdisable - optimization - specifier")
                if (WARNINGS_AS_ERRORS)
                    add_compile_options (" - Werror ") endif ()
        if (" $ {CMAKE_CXX_COMPILER_ID} " STREQUAL " Clang ")
            add_compile_options (" - Wno-gnu-zero-variadic-macro-arguments ")
            end if ()
        if (" $ {CMAKE_GENERATOR} "STREQUAL" Ninja ")
            set (CMAKE_CXX_FLAGS $ {CMAKE_CXX_FLAGS} -fcolor-diagnostics)
            set (CMAKE_C_FLAGS $ {CMAKE_C_FLAGS} -fcolor-diagnostics)
        
        if (" $ {CMAKE_CXX_COMPILER_ID} " STREQUAL " GNU ")
            add_compile_options (" - Wno-gnu-zero-variadic-macro-arguments ")
            add_compile_options (" - Wno-unused-variable ")
            add_compile_options (" - Wno-unused-function ")
            add_compile_options (" - Wno-unused-but-set-variable ")
            add_compile_options (" - fdiagnostics - color = always ")
            elseif (" $ {CMAKE_CXX_COMPILER_ID} " STREQUAL " Clang ")
            add_compile_options ( -fcolor - diagnostics )
            end if () endif () include (CTest) if (STATIC_LINKING)
    set (CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set (CMAKE_LINK_SEARCH_START_STATIC TRUE)
    set (CMAKE_LINK_SEARCH_END_STATIC TRUE)
    set_property (GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS TRUE)
        include (SYSTEM $ {KERNEL_INCLUDE_DIRS})
    find_package (LibBcc REQUIRED) 
        include_directories (SYSTEM $ {LIBBCC_INCLUDE_DIRS})
    find_package (LibBpf REQUIRED) 
        include_directories ( SYSTEM $ {LIBBPF_INCLUDE_DIRS})
    find_package (LibElf REQUIRED)
        include_directories (SYSTEM $ {LIBELF_INCLUDE_DIRS})
    find_package (LibCereal REQUIRED) 
        include_directories (SYSTEM $ {LIBCEREAL_INCLUDE_DIRS})
    find_package (Bison REQUIRED)
    find_package (Flex REQUIRED)
    bison_target (bison_parser src / parser.yy $ {CMAKE_BINARY_DIR}/parser.tab.cc VERBOSE)
    flex_target (flex_lexer src / lexer.ll $ {CMAKE_BINARY_DIR}/lexer.cc VERBOSE)
    flex_target (flex_lexer src / lexer.1 $ {CMAKE_BINARY_DIR}/lex.yy.cc)
        add_flex_bison_dependency (flex_lexer bison_parser)
        add_library(parser $ {BISON_bison_parser_OUTPUTS} ${FLEX_flex_lexer_OUTPUTS})
        add_library(lexer $ {FLEX_flex_lexer_OUTPUTS})
        add_library (bpftrace
            src / bpftrace.cc
            src / ast / ast.cpp
            src / ast / ast_visitor.cpp
            src / ast / ast_printer.cpp
            src / ast / ast_matcher.cpp
            src / ast / ast_matcher_visitor.cpp
            src / ast / ast_matcher_printer.cpp
            src / ast / ast_matcher_parser.cpp
            src / ast / ast_matcher_parser_visitor.cpp
            src / parser.tab.cc
            src / lexer.cc
            src / utils.cc
            src / utils.h
            src / btf.cc
            src / btf.h)
    target_include_directories (parser PUBLIC src src / ast $ {CMAKE_BINARY_DIR})
        include (CheckSymbolExists)
    set (CMAKE_REQUIRED_DEFINITIONS - D_GNU_SOURCE) check_symbol_exists (name_to_handle_at " sys / types.h; sys / stat.h; fcntl.h" HAVE_NAME_TO_HANDLE_AT)
    set (CMAKE_REQUIRED_DEFINITIONS)
    find_package (LibBfd)
    find_package (LibOpcodes)
    find_package (LibDw)
    if (ENABLE_SKB_OUTPUT)
    find_package (LibPcap)
    endif ()
    if (POLICY CMP0075) cmake_policy (SET CMP0075)
    endif () if (STATIC_LINKING)
    set (CMAKE_REQUIRED_LIBRARIES bcc bcc_bpf bpf elf z)
    else ()
    set (CMAKE_REQUIRED_LIBRARIES $ { LIBBCC_LIBRARIES $ {LIBBPF_LIBTRARIES}})
    endif (STATIC_LINKING) get_filename_component(LIBBCC_LIBDIR $ {LIBBCC_LIBRARIES}DIRECTORY)0
    set (CMAKE_REQUIRED_LINK_OPTIONS - L$ {LIBBCC_LIBDIR}) 
        check_symbol_exists(bcc_elf_foreach_sym " $ {LIBBCC_INCLUDE_DIRS}/bcc / bcc_elf.h" HAVE_BCC_ELF_FOREACH_SYM)
    set (CMAKE_REQUIRED_LINK_IIPTIONS - L$ {LIBBCC_LIBDIR}) 
        check_symbol_exists (bpf_attach_kfunc " $ {LIBBCC_INCLUDE_DIRS}/bcc / libbpf.h" HAVE_BCC_KFUNC)
        check_symbol_exists (bcc_usdt_addsem_probe " $ {LIBBCC_IKNCLUDE_DIRS}/ bcc / bcc_usdt.h" HAVE_BCC_USDT_ADDSEM)
        check_symbol_exists (bcc_procutils_which_so " $ {LIBBCC_INCLUDE_DIRS}/bcc / bcc_procutils.h" HAVE_BCC_WHICH_SO)
    set (CMAKE_REQUIRED_LIBRARIES) 
    set (CMAKE_REQUIRED_LINK_OPTIONS)
    if (${LIBBFD_FOUND} AND $ {LIBOPCODES_FOUND})
    set (HAVE_BFD_DISASM TRUE)
    endif () include (CheckIncludeFiles)
    check_include_file (" sys / sdt.h" HAVE_SYSTEMTAP_SYS_SDT_H)
    if (EMBED_USE_LLVM) include (embed_llvm)
    else ()
    if ($ {LLVM_REQUESTED_VERSION})
        set (LLVM_VERSION $ {LLVM_REQUESTED_VERSION})
    else ()
        set (LLVM_VERSION $ {EMBED_LLVM_VERSION})
    find_package (LLVM $ {LLVM_REQUESTED_VERSION}REQUIRED)
    else () 
        set (LLVM_VERSION $ {EMBED_LLVM_VERSION})
        find_package (LLVM $ {EMBED_LLVM_VERSION}REQUIRED)
    endif () 
    set (MIN_LLVM_MAJOR 6)
    set (MAX_LLVM_MAJOR 15)
    if (${LLVM_REQUESTED_VERSION})
    find_packkage (LLVM $ {LLVM_REQUESTED_VERSION}REQUIRED)
    else ()
        find_package (LLVM $ {EMBED_LLVM_VERSION}REQUIRED)
        endif() 
            set (MIN_LLVM_MAJOR 6)
            set (MAX_LLVM_MAJOR 15)
            if (($ {LLVM_VERSION_MAJOR} (VERSION_LESS $ {MIN_LLVM_MAJOR}) OR($ {LLVM_VERSION_MAJOR} (VERSION_GREATER $ {MAX_LLVM_MAJOR}) 
                                                                             message (SEND_ERROR "Unsupported LLVM version: $ {LLVM_VERSION_MAJOR}") {LLVM_INCLUDE_DIRS}: ${LLVM_VERSION_MAJOR}))
                                                                             message (SEND_ERROR "Only versions between $ {MIN_LLVM_MAJOR} and $ {MAX_LLVM_MAJOR} are supported."))
                                                                             message (SEND_ERROR " Specify an LLVM major version using LLVM_REQUESTED_VERSION = < major version >.")
    endif () message (STATUS "Found LLVM version: $ {LLVM_VERSION_MAJOR}.$ {LLVM_VERSION_MINOR}.$ {LLVM_VERSION_PATCH}")
        include_directories (SYSTEM $ {LLVM_INCLUDE_DIRS})
    add_definitions ($ {LLVM_DEFINITIONS})
    endif () 
    add_definitions (-DLLVM_VERSION_MAJOR=$ {LLVM_VERSION_MAJOR})
    add_definitions (-DLLVM_VERSION_MINOR=$ {LLVM_VERSION_MINOR})
    add_definitions (-DLLVM_VERSION_PATCH=$ {LLVM_VERSION_PATCH})
    set (LLVM_LINK_COMPONENTS
        Support
        Core
        IRReader
        BitReader
        BitWriter
        Object
        MC
        MCParser
        Analysis
        AsmParser
        AsmPrinter
        CodeGen
        Target)
    if (LLVM_VERSION_MAJOR VERSION_GREATER_EQUAL 10)
        set (LLVM_ORC_V2)
        set (LLVM_LINK_COMPONENTS
            ${LLVM_LINK_COMPONENTS}
            OrcJIT
            OrcTargetProcess
            JITLink)
    add_definitions (-DLLVM_ORC_V2)
    else ()
        set (LLVM_ORC_V1)
        set (LLVM_LINK_COMPONENTS
            ${LLVM_LINK_COMPONENTS}
            OrcJIT)
        add_definitions (-DLLVM_ORC_V1)
    message (STATUS "Using LLVM orcv2")
        else ()
        add_definition (-DLLVM_ORC_V1)
        endif ()
    if (EMBED_USE_LLVM)
        set (LLVM_LIBS
            $ {LLVM_LIBRARIES}
            $ {LLVM_LINK_COMPONENTS})
    else ()
        set (LLVM_LIBS
            $ {LLVM_LIBRARIES}
            $ {LLVM_LINK_COMPONENTS})
    include (embed_clang)
    else ()
    find_package (LibClang REQUIRED)
    include_directories (SYSTEM $ {LIBCLANG_INCLUDE_DIRS})
    endif ()
#BPFTARCE COMPILE DEFINTIONS
        set (BPFTRACE_FLAGS) 
        if (ALLOW_UNSAFE_PROBE)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DALLOW_UNSAFE_PROBE "HAVE_ALLOW_UNSAFE_PROBE" = 1)
            endif (HAVE_NAME_TO_HANDLE_AT)
        if (HAVE_BCC_ELF_FOREACH_SYM)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_BCC_ELF_FOREACH_SYM "HAVE_BCC_ELF_FOREACH_SYM" = 1)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -HAVE_BCC_USDT_ADDSEM "HAVE_BCC_USDT_ADDSEM" = 1)
            endif (HAVE_BCC_USDT_ADDSEM)
        if (HAVE_BCC_WHICH_SO)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_BCC_WHICH_SO "HAVE_BCC_WHICH_SO" = 1)
            endif (HAVE_BCC_WHICH_SO)
        if (LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_BCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE "HAVE_BCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE" = 1)
            endif (HAVE_BCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_BCC_KFUNC "HAVE_BCC_KFUNC" = 1)
            endif (HAVE_BCC_KFUNC)
        if (LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_BCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE "HAVE_BCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE" = 1)
            endif (HAVE_BCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)
        if (HAVE_LIBBPF_MAP_BATCH)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_LIBBPF_MAP_BATCH "HAVE_LIBBPF_MAP_BATCH" = 1)
            endif (HAVE_LIBBPF_MAP_BATCH)
        if (HAVE_LIBBPF_LINKK_CREATE)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_LIBBPF_LINK_CREATE "HAVE_LIBBPF_LINK_CREATE" = 1)
            endif (HAVE_LIBBPF_LINK_CREATE)
        if (HAVE_BFD_DISASM)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_BFD_DISASM "HAVE_BFD_DISASM" = 1)
            endif (HAVE_BFD_DISASM)
        if (LIBBFD_DIASM_FOUR_ARGS_SIGNATURE)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_LIBBFD_DISASM_FOUR_ARGS_SIGNATURE "HAVE_LIBBFD_DISASM_FOUR_ARGS_SIGNATURE" = 1)
            endif (HAVE_LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
            endif (HAVE_BFD_DISASM)
        if (LIBBPF_BTF_DUMP_FOUND_EMIT_TYPE_DECL)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL "HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL" = 1)
            endif (HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL)
        if (HAVE_LIBBPF_BPF_PROG_LOAD)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_LIBBPF_BPF_PROG_LOAD "HAVE_LIBBPF_BPF_PROG_LOAD" = 1)
            endif (HAVE_LIBBPF_BPF_PROG_LOAD)
        if (HAVE_LIBBPF_BPF_MAP_CREATE)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_LIBBPF_BPF_MAP_CREATE "HAVE_LIBBPF_BPF_MAP_CREATE" = 1)
            endif (HAVE_LIBBPF_BPF_MAP_CREATE)
        if (HAVE_LIBBPF_BTF_TYPE_CNT)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_LIBBPF_BTF_TYPE_CNT "HAVE_LIBBPF_BTF_TYPE_CNT" = 1)
            endif (HAVE_LIBBPF_BTF_TYPE_CNT)
        if (HAVE_LIBBPF_BTF_DUMP_DUMP_NEW_V0_6_0)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_LIBBPF_BTF_DUMP_DUMP_NEW_V0_6_0 "HAVE_LIBBPF_BTF_DUMP_DUMP_NEW_V0_6_0" = 1)
            endif (HAVE_LIBBPF_BTF_DUMP_DUMP_NEW_V0_6_0)
        if (HAVE_LIBBPF_BTF_DUMP_NEW_DEPRECATED)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_LIBBPF_BTF_DUMP_NEW_DEPRECATED "HAVE_LIBBPF_BTF_DUMP_NEW_DEPRECATED" = 1)
            endif (HAVE_LIBBPF_BTF_DUMP_NEW_DEPRECATED)
        if (HAVE_LIBBPF_KPROBE_MULTI)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_LIBBPF_KPROBE_MULTI "HAVE_LIBBPF_KPROBE_MULTI" = 1)
            endif (HAVE_LIBBPF_KPROBE_MULTI)
        if (LIBDW_FOUND)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_LIBDW "HAVE_LIBDW" = 1)
            endif (HAVE_LIBDW)
        if (LIBPCAP_FOUND)
        set (BPFTRACE_FLAGS $ {BPFTRACE_FLAGS} -DHAVE_LIBPCAP "HAVE_LIBPCAP" = 1)
            endif (HAVE_LIBPCAP)
        add_subdirectory (src)
        if (BUILD_TESTING)
            enable_testing()
            add_subdirectory (tests)
            add_subdirectory (resources)
        add_subdirectory (tools)
        if (ENABLE_MAN)
            add_subdirectory (man)
            endif (ENABLE_MAN)
}


#include btf.h 
# ifdef_LINUX_BTF_H
# #def _LINUX_BTF_H 1
# include <linux/types.h>
# include <linux/btf.h>
# include <linux/bpf.h>
# define BTF_TYPE_EMIT(type) ((void)(type *)0)
# #define BTF_TYPE_EMIT_ENUM (enum_val) ((void)(enum_val *)0)
# #define KF_ACQUIRE	(1 << 0)	/* kfunc is an acquire function */
#define KF_RELEASE	(1 << 1)	/* kfunc is a release function */
#define KF_RET_NULL	(1 << 2)	/* kfunc returns a pointer that may be NULL */
#define KF_KPTR_GET	(1 << 3)	/* kfunc returns reference to a kptr */
{
    if def _LINUX_BTF_H
    def _LINUX_BTF_H 1
    def BTF_TYPE_EMIT(type) ((void)(type *)0)
    def BTF_TYPE_EMIT_ENUM(enum_val) ((void)(enum_val *)0)
    def KF_ACQUIRE (1 << 0)
    def KF_RELEASE (1 << 1)
    def KF_RET_NULL (1 << 2)
    def KF_KPTR_GET (1 << 3)
    def KF_TRUSTED_ARGS (1 << 4)

    struct foo {
        int data;
        struct foo *next;
    };

    struct bar {
        int data;
        struct foo f;
    };

    struct foo *f = malloc(sizeof(struct foo));
    if (!f) {
        perror("malloc");
        return 1;
    };

    struct bar *b = malloc(sizeof(struct bar));
    if (!b) {
        perror("malloc");
        free(f);
        return 1;
    }
    set_foo_data(f, 42);
    set_bar_data(b, 84);

    struct btf;
    struct btf_member;
    struct btf_type;
    union bpf_attr;
    struct btf_id_set;
    struct btf_kfunc_id_set;
    {
        struct btf *btf;
        struct btf_member *member;
        struct btf_type *type;
        union bpf_attr *attr;
        struct btf_id_set *id_set;
        struct btf_kfunc_id_set *kfunc_id_set;
        struct module *owner;
        struct btf_id_set8 *set;
    };

    struct btf_id_dtor_kfunc
    {
        struct btf *btf;
        struct btf_type *type;
        struct btf_id_set *id_set;
        struct btf_kfunc_id_set *kfunc_id_set;
        struct module *owner;
        int (*dtor)(struct btf_id_dtor_kfunc *);
        typedef void (*btf_id_dtor_fn_t)(struct btf_id_dtor_kfunc *)(void);
    };

    extern const struct file_operation btf_fops;
    void btf_get(struct btf *btf);
    void btf_put(struct btf *btf);
    int btf_new_fd(const union bpf_attr *attr, bpfptr_t uattr);
    struct btf *btf_get_info_by_fd(const struct btf *btf, const union bpf_attr *attr, union bpf_attr__attr *uattr);
    const struct btf_type *btf_type_id_size(const struct btf *btf, u32 *type_id, u32 *ret_size);

    def BTF_SHOW_COMPACT (BTF_F_COMPACT)
    def BTF_SHOW_NONAME (BTF_F_NONAME) 
    def BTF_SHOW_PTR_RAW (BTF_F_PTR_RAW)
    def BTF_SHOW_ZERO (BTF_F_ZERO)
    def BTF_SHOW_UNSAFE (NULL << 4)
    def BTF_SHOW_RAW (BTF_F_RAW)
    void btf_type_seq_show (struct seq_file *m, const struct btf *btf, const struct btf_type *type, u32 flags)
    {
        if (flags & BTF_F_COMPACT) {
            seq_printf(m, "Compact BTF type: %s\n", btf_name_by_offset(btf, type->name_off));
        } else {
            seq_printf(m, "BTF type: %s\n", btf_name_by_offset(btf, type->name_off));
        }
    }
int btf_type_seq_show_flags (const struct btf *btf, u32 type_id, void *obj, struct seq_file *m, u64 flags);
int btf_type_snprintf_show (const struct btf *btf, u32 type_id, void *obj, char *buf, size_t size, u64 flags);
int btf_get_fd_by_id(u32 id);
    u32 btf_obj_id(const struct btf *btf);
bool btf_is_kernel(const struct btf *btf);
bool btf_is_module(const struct btf *btf);
    struct module =btf_try_get_module(const struct btf *btf);
    u32 btf_nr_types(const struct btf *btf)
bool btf_member_is_reg_int (const struct btf*btf, const struct btf_type *s,
                            const struct btf_member *m, u32 expected_offset, u32 expected_size);
int btf_find_spin_lock(const struct btf *btf, const struct btf_type *t);
int btf_find_timer (const struct btf_type *t);
    struct bpf_map_value_off *btf_parse_kptrs (const struct btf *btf, const struct btf_type *t);
bool btf_type_is_void (const struct btf_type *t);
    s32 btf_find_by_name_kind(const struct btf *btf, const char *name, u8 kind);
    const struct btf_type_skip_modifiers(const struct btf *btf, u32 id, u32 *res_id);
    const struct btf_type *btf_type_resolve_func_ptr(const struct btf *btf, u32 id, u32 *res_id);
    const struct btf_type *btf_resolve_size(const struct btf *btf, const struct btf_type *type, u32 *type_size);
    const char *btf_type_str(const struct btf_type *t);
for (i = 0, member = btf_type_member(struct_type);
    i < btf_type_vlen(struct_type); i++, member++) {
        if (member->offset == offset && member->size == size) {
            return true;
        }
    }
for (i = 0, member = btf_type_var_secinfo(datasec_type);
     i < btf_type_vlen(datasec_type); i++, member++) {
        if (member->offset == offset && member->size == size) {
            return true;
        }
    }
static inline bool btf_type_is_struct(const struct btf_type *t) {
    return BTF_INFO_KIND(t->info) == BTF_KIND_PTR; }
static inline bool btf_type_is_int(const struct btf_type *t) {
    return BTF_INFO_KIND(t->info) == BTF_KIND_INT; }
static inline bool btf_type_is_small_int(const struct btf_type *t) {
    return BTF_INFO_KIND(t->info) == BTF_KIND_INT &&
           BTF_INT_BITS(t->info) <=64; }
static inline bool btf_type_is_enum(const struct btf_type *t) {
    return BTF_INFO_KIND(t->info) == BTF_KIND_ENUM; }
static inline bool btf_is_any_enum(const struct btf_type *t) {
    return BTF_INFO_KIND(t->info) == BTF_KIND_ENUM ||
           BTF_INFO_KIND(t->info) == BTF_KIND_ENUM64; }
static inline bool btf_kind_core_compat(const struct btf_type *t1, const struct btf_type *t2) {
    return  BTF_INFO_KIND (t1->info) == BTF_INFO_KIND(t2->info) || 
    (btf_is_any enum(t1) && btf_is_any_enum(t2)); }
static inline bool str_is_empty (const char *s) {
    return !s || !s[0]; }
static inline u16 btf_kind(const struct btf_type *t) {
    return BTF_INFO_KIND(t->info); }
static inline bool btf_is_enum(const struct btf_type *t) {
    return btf_kind (t) == BTF_KIND_ENUM; }
static inline bool btf_is_enum64(const struct btf_type *t) {
    return btf_kind (t) == BTF_KIND_ENUM64; }
static inline u64 btf_enum64_value(const struct btf_enum64) {
    return ((u64) e->val_hi32 << 32) | e->val_lo32; }
static inline bool btf_is_composite(const struct btf_type *t) {
    u16 kind = btf_kind(t);
    return kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION }
static inline bool btf_is_array(const struct btf_type *t) {
    return btf_kind(t) == BTF_KIND_ARRAY; }
static inline bool btf_is_int(const struct btf_type *t) {
    return btf_kind(t) == BTF_KIND_INT; }
staic inline bool btf_is_ptr(const struct btf_type *t) {
    return btf_kind(t) == BTF_KIND_PTR; }
static inline u8 btf_int_offset(btf_type *t) {
    return BTF_INT_OFFSET (*(u32 *)(t + 1)); }
static inline u8 btf_int_encoding (const struct btf_type *t) {
    return BTF_INT_ENCODING (*(u32 *)(t + 1)); }
static inline bool btf_type_is_scalar(const struct btf_type *t) {
    return btf_type_is_int(t) || btf_type_is_enum(t); }
static inline bool btf_type_is_typedef(const struct btf_type *t) {
    return BTF_INFO_KIND(t->info) == BTF_KIND_TYPEDEF; } 
static inline bool btf_type_is_func(const struct btf_type *t) {
    return BTF_INFO_KIND(t->info) == BTF_KIND_FUNC; }
static inline bool btf_type_is_func_proto(const struct btf_type *t) {
    return BTF_INFO_KIND(t->info) == BTF_KIND_FUNC_PROTO; }
static inline bool btf_type_is_var(const struct btf_type *t) {
    return BTF_INFO_KIND(t->info) == BTF_KIND_VAR }
static inline bool btf_type_is_type_tag(const struct btf_type *t) {
    return BTF_INFO_KIND(t->info) ==BTF_KIND_TYPE_TAG; }
static inline bool btf_type_is_struct(const struct btf_type *t) {
    u8 kind = BTF_INFO_KIND(t->info);
    return kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION; }
static inline u16 btf_type_vlen(const struct btf_type *t) {
    return BTF_INFO_VLEN(t->info); }
static inline u16 btf_vlen(const struct btf_type *t) {
    return btf_type_vlen(t); }
static inline u16 btf_func_linkage(const struct btf_type *t) {
    return BTF_INFO_VLEN(t->info); }
static inline bool btf_type_kflag(const struct btf_type *t) {
    return BTF_INFO_KFLAG(t->info); }
static inline u32__btf_member_bit_offset(const struct btf_type *struct_type, const struct btf_member *member){
    return btf_type_kflag(struct_type) ? BTF_MEMBER_BIT_OFFSET(member->offset) : member->offset; }
static inline u32__btf_member_bitfield_size(const struct btf_type *struct_type, const struct btf_member *member) {
    return btf_type_kflag(struct_type) ? BTF_MEMBER_BITFIELD_SIZE(member->offset) : member->size; }
static inline struct btf_member *btf_members(const struct btf_type *t) {
    return (struct btf_member *)(t + 1); }
static inline u32__btf_member_bit_offset(const struct btf_type *t, u32 member_idx) {
    return __btf_member_bit_offset(t, m); }
satic inline u32__btf_member_bitfield_size(const struct btf_type *t, u32 member_idx) {
    const struct btf_member *m = btf_members(t) + member_idx;
    return __btf_member_bitfield_size(t, m); }
static inline const struct  tf_member *btf_type_member(const struct btf_type *t) {
    return (const struct btf_member *)(t + 1); }
static inline btf_array *btf_array(const struct btf_type *t) {
    return (btf_array *)(t + 1); }
static inline struct btf_enum *btf_enum(const struct btf_type *t) {
    return (struct btf_enum*)(t + 1); }
static inline struct btf_enum64(const struct btf_type *t) {
    return (struct btf_enum64 *)(t + 1); }
static inline const struct btf_type_var_secinfo(const struct btf_type *t) {
    return (const struct btf_var_secinfo *)(t + 1);
static inline struct btf_param *btf_params(const struct btf_type *t) {
    return (struct btf_param *)(t + 1); }
}

{
    struct bpf_prog;
    const struct btf_type *btf_type_by_id(const struct btf *btf, u32 type_id);
    const char *btf_name_by_offset(const struct btf *btf; u32 offset);
    struct btf *btf_parsea_vmlinux(void);
    struct btf *bpf_prog_get_target_btf(const struct bpf_prog *prog);
    u32 *btf_kfunc_id_set_contains(const struct btf *btf, enum bpf_prog_type prog_type, u32 kfunc_btf_id);
    int register_btf_kfunc_id_set(enum bpf_prog_type prog_type, const struct btf_kfunc_id_set *s);
    s32 btf_find_dtor_kfunc(struct btf *btf, u32 btf_id);
    int register_btf_id_dtor_kfunc (const struct btf_id_dtor_kfunc *dtors, u32 add_cnt, struct module *owner);
        else static inline const struct btf_type *btf_type_by_id(const struct btf *btf, u32 type_id) {
            return NULL;
        }
    static inline const char *btf_name_by_offset(const struct btf *btf, u32 offset) {
        return NULL;
    }
    static inline u32 *btf_kfunc_id_set_contains(const struct btf *btf, enum bpf_prog_type prog_type, u32 kfunc_btf_id) {
        return NULL;
    }
    static inline
    int register_btf_kfunc_id_set(enum bpf_prog_type prog_type, const struct btf_kfunc_id_set *s) {
        return 0;
    }
    static inline s32 btf_find_dtor_kfunc(struct btf *btf, u32 btf_id) {
        return -EMOENT;
    }
    static inline
    int register_btf_id_dtor_kfuncs(const struct btf_id_dtor_kfunc *dtors, u32 add_cnt, struct module *owner) {
        return 0;
    }
}

{
/* Figure out the size of a type_id.  If type_id is a modifier
	* (e.g. const), it will be resolved to find out the type with size.
	*
	* For example:
	* In describing " const void *",  type_id is " const " and " const "
	* refers to " void *".  The return type will be " void *".
	*
	* If type_id is a simple " int ", then return type will be " int ".
	*
	* @btf: struct btf object
	* @type_id: Find out the size of type_id. The type_id of the return
	*           type is set to *type_id.
	* @ret_size: It can be NULL.  If not NULL, the size of the return
	*            type is set to *ret_size.
	* Return: The btf_type (resolved to another type with size info if needed).
	*         NULL is returned if type_id itself does not have size info
	*         (e.g. void) or it cannot be resolved to another type that
	*         has size info.
	*         *type_id and *ret_size will not be changed in the
    *         NULL return case.
	*/
}

{
    #includearch/arch.h
    OBJCOPYFLAGS = -O binary - R.note - R.note.gnu.build - id - R.comment - S LINUX_START_TEXT = $$ ($ (READELF) - h 
           vmlinux | grep " " | grep - o 0x.*)UIMAGE_LOADADDR = $ (CONFIG_LINUX_LINK_BASE) UIMAGE_ENTRYADDR = $
           (LINUX_START_TEXT) targets += vmlinux.bin targets += vmlinux.bin.gz targets += vmlinux.bin.lzma targets += uImage.bin
           targets += uImage.gz target += uImage lzma $ (obj) / vmlinux.bin: vmlinux FORCCE $ (call if_changed, objcopy) $ 
           (obj) / vmlinux.bin.gz: $ (obj) / vmlinux.bin FORCE $ (call if_changed, gzip) $ (obj) / vmlinux.bin.lzma: $ (obj) /
           vmlinux.bin FORCE $ (call if_changed, lzma) $ (obj) / uImage.bin: $ (obj) / vmlinux.bin FORCE $ (call if_changed, uImaghe, none) $ 
           (obj) / uImage.gz: $ (obj) / vmlinux.bin.gz FORCE $ (call if_changed, uImage, gzip) $ (obj) / uImage.lzma: $ (obj) /
           vmlinux.bin.lzma FORCE $ (call if_changed, uImage, lzma)                                                                                     
}
 {
    CONFIG_SYSVIPC = yield
    CONFIG_POSIX_MQUEUE = yield
    CONFIG_CROSS_MEMORY_ATTACH = yield
    CONFIG_NO_HZ_IDLE = yield
    CONFIG_HIGH_RES_TIMERS = yield
    CONFIG_IKCONFIG = yield
    CONFIG_IKCONFIG_PROC = yield
    CONFIG_NAMESPACES = yield
    CONFIG_UTS_NS = yield
    CONFIG_PID_NS = yield
    CONFIG_BLK_DEV_INITRD = yield
    CONFIG_EMBEDDED = yield
    CONFIG_PERF_EVWENTS = yield
    CONFIG_ISA_ARCOMPACT = yield
    CONFIG_MODULES = yield
    CONFIG_MODULE_FORCE_LOAD = yield
    CONFIG_MODULE_UNLOAD = yield
    CONFIG_MODULE_FORCE_UNLOAD = yield
    CONFIG_PARTITION_ADVANCED = yield
    CONFIG_ARC_PLAT_AXS10X = yield
    CONFIG_AXS101 = yield
    CONFIG_ARC_CACHE_LINE_SHIFT = yield
    CONFIG_ARC_BUILTIN_DTB_NAME = "axs101"
    CONFIG_PREEMPT = yield
    CONFIG_COMPACTION = yield
    CONFIG_NET = yield
    CONFIG_PACKET = yield
    CONFIG_UNIX = yield
    CONFIG_NET_KEY = yield
    CONFIG_INET = yield
    CONFIG_IP_PNP = yield
    CONFIG_IP_PNP_DHCP = yield
    CONFIG_IP_PNP_BOOTP = yield
    CONFIG_IP_PNP_RARP = yield
    CONFIG_INET_XFRM_MODE_TRANSPORT = yield
    CONFIG_INET_XFRM_MODE_TUNNEL = yield
    CONFIG_INET_XFRM_MODE_BEET = yield
    CONFIG_IPV6 = yield
    CONFIG_DEVTMPFS = yield
    CONFIG_SCSI = yield
    CONFIG_BLK_DEV_SD = yield
    CONFIG_NETDEVICES = yield
    CONFIG_NET_VENDOR_ARC = yield
    CONFIG_NET_VENDOR_BROADCOM = yield
    CONFIG_NET_VENDOR_INTEL = yield
    CONFIG_NET_VENDOR_MARVELL = yield
    CONFIG_NET_VENDOR_MICREL = yield
    CONFIG_NET_VENDOR_MATSEMI = yield
    CONFIG_NET_VENDOR_SEEQ = yield
    CONFIG_STMMAC_ETH = yield
    CONFIG_NET_VENDOR_VIA = yield
    CONFIG_NET_VENDOR_WIZNET = yield
    CONFIG_NATIONAL_PHY = yield
    CONFIG_USB_NET_DRIVERS = yield
    CONFIG_INPUT_EVDEV = yield
    CONFIG_MOUSE_PS2_TOUCHKIT = yield
    CONFIG_MOUSE_SERIAL = yield
    CONFIG_MOUSE_SYNAPYICS_USB = yield
    CONFIG_SERIAL_8250 = yield
    CONFIG_SERIAL_8250_CONSOLE = yield
    CONFIG_SERIAL_8250_DW = yield
    CONFIG_SERIAL_OF_PALTFORM = yield
    CONFIG_HW_RANDOM = yield
    CONFIG_I2C = yield
    CONFIG_I2C_CHARDEV = yield
    CONFIG_I2C_DESIGNWARE_PLATFORM = yield
    CONFIG_DRM = m 
    CONFIG_DRM_I2C_ADV7511 = yield
    CONFIG_DRM_ARCPGU = yield
    CONFIG_FB = yield
    CONFIG_FRAMBUFFER_CONSOLE = yield 
    CONFIG_LOGO = yield
    CONFIG_LOGO_LINUX_MONO = yield
    CONFIG_LOGO_LINUX_VGA16 = yield
    CONFIG_LOGO_LINUX_CLUT224 = yield
    CONFIG_USB_EHCI_HCD = yield
    CONFIG_USB_EHCI_HCD_PLATFORM = yield
    CONFIG_USB_OHCI_HCD = yield
    CONFIG_USB_OHCI_HCD_PLATFORM = yield
    CONFIG_USB_STORAGE = yield
    CONFIG_MMC_SDHCI = yield
    CONFIG_MMC_SDHCI_PLATFORM = yield
    CONFIG_MMC_DW = yield
    CONFIG_EXT3_FS = yield
    CONFIG_MSDOS_FS = yield
    CONFIG_VFAT_FS = yield
    CONFIG_NTFS_FS = yield
    CONFIG_TMPFS_FS = yield
    CONFIG_NFS_FS = yield
    CONFIG_NFS_V3_ACL = yield
    CONFIG_NFS_CODEPAGE_437 = yield
    CONFIG_NLS_ISO8859_1 = yield
    CONFIG_ENABLE_MUST_CHECK = yield
    CONFIG_STRIP_ASM_SYMS = yield
    CONFIG_SOFTLOCKUP_DETECTOR = yield
    CONFIG_DEFAULT_HUNG_TASK_TIMEOUT = 10
    CONFIG_SCHED_DEBUG = yield
    CONFIG_DEBUG_PREEMPT = yield
    CONFIG_FTRACE = yield
 }

{
    OBJCOPYFLAGS = -O binary - R.note - R.note.gnu.build - id - R.comment - S 
    LINUX_START_TEXT = $$($(READELF) -h vmlinux | \
                grep "Entry point address" | grep -o 0x.*)
    
    UIMAGE_LOADADDR = $(CONFIG_LINUX_LINK_BASE)
    UIMAGE_ENTRYADDR = $(LINUX_START_TEXT)

    targets += vmlinux.bin
    targets += vmlinux.bin.gz
    targets += vmlinux.bin.lzma
    targets += uImage.bin
    targets += uImage.gz
    targets += uImage.lzma

    $(obj)/vmlinux.bin: vmlinux FORCE $(call if_changed, objcopy);
    $(obj)/vmlinux.bin.gz: $(obj)/vmlinux.bin FORCE $(call if_changed, gzip)
    $(obj)/vmlinux.bin.lzma: $(obj)/vmlinux.bin FORCE $(call if_changed, uimage, none)
    $(obj)/uImage.bin: $(obj)/vmlinux.bin FORCE $(call if_changed, uimage, none)
    $(obj)/uImage.gz: $(obj)/vmlinux.bin.lzma FORCE $(call if_changed, uimage, lzma)
    
}

{
    1/3.1415=12 *Z/n = 0(-1)^n (6*n) *!) / (3*n) *! (1*n *!) ^ 3 = 2/3 *3.1415
}

{
    #bpftrace security check
    printf("Tracing cap_capable syscalls.. Hit Ctrl-C to end.\n");
    printf("%-9s %-6s %-6s %-16s %-4s %-20s AUDIT\n", "TIME", "UID", "PID", "COMM", "CAP", "NAME");
    {
        @cap[0] = "CAP_CHOWN";
        @cap[1] = "CAP_DAC_OVERRIDE";
        @cap[2] = "CAP_DAC_READ_SEARCH";
        @cap[3] = "CAP_FOWNER";
        @cap[4] = "CAP_FSETID";
        @cap[5] = "CAP_KILL";
        @cap[6] = "CAP_SETGID";
        @cap[7] = "CAP_SETUID";
        @cap[8] = "CAP_SETPCAP";
        @cap[9] = "CAP_LINUX_IMMUTABLE";
        @cap[10] = "CAP_NET_BROADCAST";
        @cap[11] = "CAP_NET_ADMIN";
        @cap[12] = "CAP_NET_RAW";
        @cap[13] = "CAP_IPC_LOCK";
        @cap[14] = "CAP_IPC_LOCK";
        @cap[15] = "CAP_IPC_OWNER";
        @cap[16] = "CAP_SYS_MODULE";
        @cap[17] = "CAP_SYS_RAWIO";
        @cap[18] = "CAP_SYS_CHROOT";
        @cap[19] = "CAP_SYS_PTRACE";
        @cap[20] = "CAP_SYS_PACCT";
        @cap[21] = "CAP_SYS_ADMIN";
        @cap[22] = "CAP_SYS_BOOT";
        @cap[23] = "CAP_SYS_NICE";
        @cap[24] = "CAP_SYS_RESOURCE";
        @cap[25] = "CAP_SYS_TIME";
        @cap[26] = "CAP_SYS_TTY_CONFIG";
        @cap[27] = "CAP_MKNOD";
        @cap[28] = "CAP_LEASE";
        @cap[29] = "CAP_AUDIT_WRITE";
        @cap[30] = "CAP_AUDIT_CONTROL";
        @cap[31] = "CAP_SETFCAP";
        @cap[32] = "CAP_MAC_OVERRIDE";
        @cap[33] = "CAP_MAC_ADMIN";
        @cap[33] = "CAP_SYSLOG";
        @cap[34] = "CAP_WAKE_ALARM";
        @cap[35] = "CAP_BLOCK_SUSPEND";
        @cap[36] = "CAP_AUDIT_READ";
        @cap[37] = "CAP_PERFMON";
        @cap[38] = "CAP_BPF";
        @cap[39] = "CAP_CHECKPOINT_RESTORE";
    }
}

{
    kprobe:cap_cappable
    {
        $crap = arg2;
        $crap = arg3;
    }
}

{
#linux
#eBPF
#1/usr/bin/env bpftrace
/*
/*
/*Black I/O tracing tool, latency...
/*
/*remember (sysadmin)
*/
#ifndef
#include <linux/blkdev.h>
#include (BTF variables)
#include <linux/blk-mq.h>
#endif
}

{
    (kprobe: blk_account_io_start <probe>)

    @start[arg0] = nsecs;
    @iopid[arg0] = PID;
    @iocomm[] = COMM

    menuconfig ASYMMETRIC_KEY_TYPE
        bool "asymmetric (public - key cryptographic) key type";
        depends on KEYS
        help 
            This option provides support for a key type that holds the data for the asymmetric keys used for public key cryptographic such as encryption, decryption, signature generation and signature verification.
            if ASYMMETRIC_KEY_SUBTYPE
        config ASYMMETRIC_PUBLIC_KEY_SUBTYPE
            tristate "Asymmetric publiuc - key crypto algorithm subtype";
            select MPILIB
            select CRYPTO_HASH_INFO
            select CRYPTO_AXCIPHER
            select CRYPTO_HASH
            help 
                This option provides support for asymmetric public key type handling. If signature generation and/or verification are to be used appropriate hash algorithms (such as SHA-1) must be available. ENOPKG will reported if requisite algorithm is unavailable.
        config X509_CERTIFICATE_PARSER
            tristate "X.509 certificate parser"
            depends on ASYMMETRIC_PUBLIC_KEY_SUBTYPE
            select ASN1
            select OID_REGISTRY
        help
            This option provides support for pursuing X.509 format blobs for key data and provides the ability to instantiate a crypto key roma public key packet found inside the certificate.
}

{
    name: CI
    on: [push, pull_request]
    jobs:
        clang-format: 
        #Only run clang-format on pull requests.
        if: "github.event_name == 'pull_request'"
        runs-on: ubuntu-latest
        steps: 
            uses: actions/checkout@v2
            with:
                submodules: recursive 
        -   name: Install clang-format 
            run: sudo apt-getinstall clang-format
        -   name: Download git-clang-format
            run: wget http://raw.githubusercontent/llvm-mirror/clang/master/tools/clang-format/git-clang-format
        -   name: Install git-clang-format
            run: sudo install -t/bin git-clang-format
        -   name: Fetch origin master
            run: git fetch --no-tags --prune --depth = 1 origin master
        -   name: clang-format
            run: git clang-format origin/master
        -   name: diff
            run: git diff --exit-code 
    build_test: 
        runs-on: ubuntu-latest
        strategy:
            matrix:
                env: 
                -   NAME: LLVM 10 Debug
                    TYPE: Debug
                    LLVM_VERSION: 10
                    RUN_ALL_TESTS: 1
                    RUNTIME_TEST_DISABLE: probe.kprobe_offset_fail_size,usdt. "usdt probes - file based semaphore activation multi process"
                    TOOLS_TEST_OLDVERSION: biosnoop.bt tcpdrop.bt 
                    BASE: focal
                    VENDOR_GTEST: ON 
                -   NAME: LLVM 10 Release
                    TYPE: Release
                    LLVM_VERSION: 10
                    RUN_ALL_TESTS: 1
                    RUNTIME_TEST_DISABLE: probe.kprobe_offset_fail_size,usdt. "usdt probes - file based semaphore activation multi process"
                    TOOLS_TEST_OLDVERSION: biosnoop.bt tcpdrop.bt 
                    BASE: focal
                    VENDOR_GTEST: ON 
                -   NAME: LLVM 10 Clang Debug
                    TYPE: Debug
                    LLVM_VERSION: 10
                    CC: clang-10
                    CXX: clang++-10
                    RUN_ALL_TESTS: 1
                    RUNTIME_TEST_DISABLE: probe.kprobe_offset_fail_size,usdt. "usdt probes - file based semaphore activation multi process"
                    TOOLS_TEST_OLDVERSION: biosnoop.bt tcpdrop.bt 
                    BASE: focal
                    VENDOR_GTEST: ON 
                -   NAME: LLVM 11 Debug
                    TYPE: Debug
                    LLVM_VERSION: 11
                    RUN_ALL_TESTS: 1
                    RUNTIME_TEST_DISABLE: probe.kprobe_offset_fail_size,usdt. "usdt probes - file based semaphore activation multi process"
                    TOOLS_TEST_OLDVERSION: biosnoop.bt tcpdrop.bt 
                    BASE: focal
                    VENDOR_GTEST: ON 
                -   NAME: LLVM 12 Release
                    TYPE: Release
                    LLVM_VERSION: LLVM 12 Release
                    RUN_ALL_TESTS: 1
                    RUNTIME_TEST_DISABLE: probe.kprobe_offset_fail_size,usdt. "usdt probes - file based semaphore activation multi process"
                    TOOLS_TEST_OLDVERSION: biosnoop.bt tcpdrop.bt 
                    BASE: focal
                    VENDOR_GTEST: ON 
                -   NAME: LLVM 13 Release
                    TYPE: Release
                    LLVM_VERSION: 14
                    RUN_ALL_TESTS: 1
                    RUNTIME_TEST_DISABLE: probe.kprobe_offset_fail_size,usdt."usdt probes - file based semaphore activation multi process"
                    TOOLS_TEST_OLDVERSION: biosnoop.bt tcpdrop.bt 
                    BASE: focal
                    VENDOR_GTEST: ON 
                -   NAME: LLVM 15 Release
                    TYPE: Release
                    LLVM_VERSION: 15
                    RUN_ALL_TESTS: 1
                    RUNTIME_TEST_DISABLE: probe.kprobe_offset_fail_size,usdt."usdt probes - file based semaphore activation multi process"
                    TOOLS_TEST_OLDVERSION: biosnoop.bt tcpdrop.bt 
                    BASE: focal
                    VENDOR_GTEST: ON 
                -   NAME: Memleak test (LLVM 12 Debug) 
                    TYPE: Debug
                    LLVM_VERSION: 12
                    RUN_MEMLEAK_TEST: 1
                    RUN_TESTS: 0
                    VENDOR_GTEST: ON
                -   NAME: Memleak test (LLVM 12 Release)
                    TYPE: Release
                    LLVM_VERSION: 12
                    BASE: focal
                    RUN_MEMLEAK_TEST: 1
                    RUN_TESTS: 0
                    VENDOR_GTEST: ON
    steps:
    - uses: actions/checkout@v2
      with:
        submodules: recursive
    - name: get date
      id: get-date
      run: echo "::set-output name=date::$(date +%Y.week%g-%m-%d)"
      shell: bash
    - name: Cache docker image
      env: ${{matrix.env}}
      id: cache-docker-image
      run: |
        echo "Cache docker image for ${{ matrix.env.NAME }}"
        echo "Cache key: ${{ runner.os }}-${{ matrix.env.NAME }}-${{ steps.get-date.outputs.date }}"
        echo "Cache path: /tmp/bpftrace-docker-${{ matrix.env.NAME }}"
        echo "::set-output name=key::${{ runner.os }}-${{ matrix.env.NAME }}-${{ steps.get-date.outputs.date }}"
        echo "::set-output name=path::/tmp/bpftrace-docker-${{ matrix.env.NAME }}"
      uses: actions/cache@v2
      with: 
        path: /tmp/bpftrace-docker-${{ matrix.env.NAME }}
        key: ${{ runner.os }}-${{ matrix.env.NAME }}-${{ steps.get-date.outputs.date }}
    - name: Build docker container 
    if: steps.cache-docker-image.outputs.cache-hit != 'true'
        env: ${{matrix.env}}
        run: |
            echo "Building docker container for ${{ matrix.env.NAME }}"
            docker build -t bpftrace:${{ matrix.env.NAME }} \
                --build-arg LLVM_VERSION=${{ matrix.env.LLVM_VERSION }} \
                --build-arg BASE=${{ matrix.env.BASE }} \
                --build-arg CC=${{ matrix.env.CC }} \
                --build-arg CXX=${{ matrix.env.CXX }} \
                --build-arg TYPE=${{ matrix.env.TYPE }} \
                --build-arg RUN_ALL_TESTS=${{ matrix.env.RUN_ALL_TESTS }} \
                --build-arg RUN_MEMLEAK_TEST=${{ matrix.env.RUN_MEMLEAK_TEST }} \
                --build-arg RUNTIME_TEST_DISABLE=${{ matrix.env.RUNTIME_TEST_DISABLE }} \
                --build-arg TOOLS_TEST_OLDVERSION=${{ matrix.env.TOOLS_TEST_OLDVERSION }} \
                --build-arg VENDOR_GTEST=${{ matrix.env.VENDOR_GTEST }} \
                -f .github/workflows/Dockerfile.$BASE \
                docker / &&  mkdir -p /tmp/bpftrace-docker-${{ matrix.env.NAME }} && \
                docker save bpftrace:${{ matrix.env.NAME }} -o /tmp/bpftrace-docker-${{ matrix.env.NAME }}/bpftrace.tar
}
{
    - name: Build docker container
      if: steps.docker-cache.outputs.cache-hit != 'true'
      env: ${{matrix.env}}
      run: > 
        docker __build_class__
        --build-arg LLVM_VERSION = $LLVM_VERSION
        -t bpftrace-builder-$BASE-llvm-$LLVM_VERSION
        -f docker/Dockerfile.$BASE 
        docker/ &&
        mkdir -p /tmp/docker-save &&
        docker save bpftrace-builder-$BASE-llvm-$LLVM_VERSION -o /tmp/docker-save/i.tar 
    - name: Load the cached docker image (if available)
      if: steps.docker-cache.outputs.cache-hit == 'true'
      run: >
        docker load --input /tmp/docker-save/i.tar 
    - name: Load kernel modules
#nf_tables and xfs are necessary for testing kernel modules BTF support.
    run: |
        sudo modprobe nf_tables
        sudo modprobe xfs
    - name: Build and test
      env: ${{matrix.env}}
      run: >
        docker run --privilleged
        -v $(pwd):$(pwd)
        -w $(pwd)
        -v /sys/kernel/debug:/sys/kernel/debug:rw 
        -v /lib/modules:/lib/modulr:ro
        -v /usr/src:/usr/src:ro 
        -e RUN_TESTS = ${RUN_ALL_TESTS}
        -e RUN_ALL_TESTS = ${RUN_ALL_TESTS}
        -e RUN_MEMLEAK_TEST = "${RUN_MEMLEAK_TEST}"
        -e CMAKE_EXTRA_FLAGS = "${CMAKE_EXTRA_FLAGS}"
        -e RUNTIME_TEST_DISABLE = "${RUNTIME_TEST_DISABLE}"
        -e VENDOR_GTEST = "${VENDOR_GTEST}"
        -e CC = "${CC}"
        -e CXX = "${CXX}"
        -e GTEST_FILTER = "${GTEST_FILTER}"
        -e TOOLS_TEST_DISABLE = "${TOOLS_TEST_DISABLE}"
        -e TOOLS_TEST_OLDVERSION = "${TOOLS_TEST_OLDVERSION}"
        bpftrace-builder-$BASE-llvm-$LLVM_VERSION
        ${PWD}/build-$TYPE-$BASE 
        $TYPE 
        -js(nproc)
    irc:
    #notify IRC of build failures on pushes only if we are running from the main repo.
    #we don't want this rule to trigger from forked repos.
        needs:
            - build_test
        if: "failure() && github.event_name == 'push' && gtihub.ref == 'refs/heads/master' && github.repository == 'iovisor/bpftrace'"
        runs-on: ubuntu-latest
        steps:
        - name: Message channel
          uses: rectalogic/notify-irc@v1
          with: 
            nickname: bpftrace-ci-bot 
            server: irc.oftc.net 
            port: 6667
            tls: False
            channel: "#bpftrace"
            message: | 
                master is broken at https://github.com/iovisor/bpftrace/commit/${{github.sha}}
}

{
    
}








    

}





{
#bpftrace security check
    printf (Tracing cap_capable syscalls.. Hit Ctrl-C to end. \n)













     









}
    #include <linux/types.h>

{
//#COPYRIGHT
	The Linux Kernel is provided under:SPDX -License -Identifier:GPL - 2.0 WITH Linux - syscall - note 
    Being under the terms of the GNU General Public License version 2 only, according with:LICENSES / preferred / GPL - 2.0 With an explicit syscall exception, 
    as stated at:LICENSES / exceptions / Linux - syscall - note In addition, other licenses may also apply.
    Please see:Documentation / process / license - rules.rst for more details. 
    All contributions to the Linux Kernel are subject to this COPYING file.}



         

    




        










    
    











            

            
















    
    



