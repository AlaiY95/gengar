use ethers::{prelude::Lazy, types::Bytes};

pub static GENGAR_BYTECODE: Lazy<Bytes> = Lazy::new(|| {
    "0x60806040526004361061002c575f3560e01c80638da5cb5b14610150578063b29a81401461018a57610033565b3661003357005b5f546001600160a01b0316331461007d5760405162461bcd60e51b81526020600482015260096024820152682727aa2fa7aba722a960b91b60448201526064015b60405180910390fd5b604051365f3560c01c438114610091575f80fd5b5060085b8181101561014e57803560f81c600182013560601c601583013560601c6029840135604985013560698601955063a9059cbb60e01b88528360048901528160248901525f8060448a5f875af16100e9575f80fd5b63022c0d9f60e01b8852848015610107576001811461011857610125565b8160048a01525f60248a0152610125565b5f60048a01528160248a01525b50505050306044860152608060648601525f8060a4875f855af1610147575f80fd5b5050610095565b005b34801561015b575f80fd5b505f5461016e906001600160a01b031681565b6040516001600160a01b03909116815260200160405180910390f35b348015610195575f80fd5b5061014e6101a4366004610243565b5f546001600160a01b031633146101e95760405162461bcd60e51b81526020600482015260096024820152682727aa2fa7aba722a960b91b6044820152606401610074565b811580156101fe576001811461022e57505050565b60405163a9059cbb60e01b81523360048201528260248201525f806044835f885af1610228575f80fd5b50505050565b5f805f8085335af161023e575f80fd5b505050565b5f8060408385031215610254575f80fd5b82356001600160a01b038116811461026a575f80fd5b94602093909301359350505056fea2646970667358221220b4287f9ce11eb4700ef59df6c880df5216f588fdc8907160c1d5f2f87bdddd6a64736f6c63430008140033".parse().unwrap()
});